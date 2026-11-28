"""Shared SQLite, validation, security and audit helpers for ParcelTrack Lite."""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Depends, HTTPException, Request

ROOT = Path(__file__).resolve().parents[1]
PH = PasswordHasher(time_cost=3, memory_cost=19456, parallelism=2)
# Equal-cost fallback for unknown users; generated once per Python process.
DUMMY_PASSWORD_HASH = PH.hash('not-an-actual-user-password')
EMAIL_RE = re.compile(r'^[^\s@]{1,64}@[^\s@]{1,190}$')
PHONE_RE = re.compile(r'^[0-9]{8,15}
TRACK_RE = re.compile(r'^PT-[A-F0-9]{24}$')
STATUSES = ('Registered', 'Assigned', 'Out for Delivery', 'Delivered', 'Failed')
LOG = logging.getLogger('parceltrack')


def load_environment() -> None:
    """Read KEY=value from private project-root .env, keeping real env authoritative."""
    file = ROOT / '.env'
    if not file.is_file():
        return
    for line in file.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        if re.fullmatch(r'[A-Z][A-Z0-9_]*', k.strip()):
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def db_connection(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 10000')
    return conn


def db(request: Request):
    conn = db_connection(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('seller','rider','admin')),
 is_active INTEGER NOT NULL DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0,
 locked_until INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS parcels (
 id INTEGER PRIMARY KEY, tracking_number TEXT NOT NULL UNIQUE,
 seller_id INTEGER NOT NULL REFERENCES users(id), rider_id INTEGER REFERENCES users(id),
 recipient_name TEXT NOT NULL, recipient_phone TEXT NOT NULL,
 recipient_address TEXT NOT NULL, weight_grams INTEGER NOT NULL CHECK(weight_grams > 0),
 status TEXT NOT NULL CHECK(status IN ('Registered','Assigned','Out for Delivery','Delivered','Failed')),
 proof_path TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT
);
CREATE INDEX IF NOT EXISTS parcels_seller_idx ON parcels(seller_id);
CREATE INDEX IF NOT EXISTS parcels_rider_idx ON parcels(rider_id);
CREATE TABLE IF NOT EXISTS status_history (
 id INTEGER PRIMARY KEY, parcel_id INTEGER NOT NULL REFERENCES parcels(id) ON DELETE CASCADE,
 status TEXT NOT NULL, actor_user_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_parcel_idx ON status_history(parcel_id);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, actor_user_id INTEGER REFERENCES users(id),
 event TEXT NOT NULL, entity_id INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
 rate_key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
);
'''


def initialize(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = db_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def bad(message: str, code: int = 400) -> None:
    raise HTTPException(status_code=code, detail=message)


def text_value(value: Any, field: str, min_len: int, max_len: int) -> str:
    if not isinstance(value, str):
        bad(f'{field} is invalid.')
    value = value.strip()
    if not (min_len <= len(value) <= max_len) or any(ord(ch) < 32 for ch in value):
        bad(f'{field} must have {min_len}-{max_len} characters.')
    return value


def valid_email(value: Any) -> str:
    value = text_value(value, 'Email', 3, 254).lower()
    if not EMAIL_RE.fullmatch(value):
        bad('Email format is invalid.')
    return value


def valid_password(value: Any) -> str:
    if not isinstance(value, str) or not (10 <= len(value) <= 128):
        bad('Password must be 10-128 characters.')
    return value


def valid_phone(value: Any) -> str:
    # Preserve digits exactly, including any leading zero.
    # Hyphens, whitespace and prefixes such as + are not accepted.
    if not isinstance(value, str) or not PHONE_RE.fullmatch(value):
        bad('Phone must contain 8-15 digits, without hyphens or spaces.')
    return value

def audit(conn: sqlite3.Connection, event: str, user_id: int | None, entity_id: int | None = None) -> None:
    conn.execute('INSERT INTO audit_logs(actor_user_id,event,entity_id,created_at) VALUES(?,?,?,?)',
                 (user_id, event, entity_id, utc_now()))


def client_ip(request: Request) -> str:
    # Accepted only after a shared-secret check, and the API only listens on loopback.
    ip = request.headers.get('X-Client-IP', '') if request.app.state.test_mode or request.client and request.client.host in ('127.0.0.1', '::1', 'testclient') else ''
    if not ip:
        ip = request.client.host if request.client else 'unknown'
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return 'unknown'


def throttle(conn: sqlite3.Connection, name: str, client: str, limit: int, window: int) -> None:
    # Hash the identifier so IP addresses/emails are not stored in this table.
    key = hashlib.sha256(f'{name}|{client}'.encode()).hexdigest()
    now = int(time.time())
    with conn:
        row = conn.execute('SELECT window_start,count FROM rate_limits WHERE rate_key=?', (key,)).fetchone()
        if row is None or now - row['window_start'] >= window:
            conn.execute('INSERT INTO rate_limits(rate_key,window_start,count) VALUES(?,?,1) '
                         'ON CONFLICT(rate_key) DO UPDATE SET window_start=excluded.window_start,count=1',
                         (key, now))
        elif row['count'] >= limit:
            bad('Too many requests. Please try again later.', 429)
        else:
            conn.execute('UPDATE rate_limits SET count=count+1 WHERE rate_key=?', (key,))


def issue_token(conn: sqlite3.Connection, uid: int) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn.execute('INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at) VALUES(?,?,?,?,?)',
                 (hashlib.sha256(token.encode()).hexdigest(), uid, now, now, now + 12 * 3600))
    return token


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(request: Request, conn: sqlite3.Connection = Depends(db)) -> dict:
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer ') or len(header) > 256:
        bad('Authentication required.', 401)
    token = header[7:]
    row = conn.execute('''SELECT u.id,u.name,u.email,u.role,u.is_active,s.last_seen,s.expires_at
                          FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?''',
                       (token_hash(token),)).fetchone()
    now = int(time.time())
    if not row or not row['is_active'] or row['expires_at'] <= now or now-row['last_seen'] > 30 * 60:
        bad('Session expired. Please log in again.', 401)
    conn.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?', (now, token_hash(token)))
    conn.commit()
    return dict(row)


def role_guard(*roles: str):
    def check(user: dict = Depends(current_user)) -> dict:
        if user['role'] not in roles:
            bad('Access denied.', 403)
        return user
    return check


def parcel_access(conn: sqlite3.Connection, parcel_id: int, user: dict) -> sqlite3.Row:
    if user['role'] == 'admin':
        query, params = 'SELECT * FROM parcels WHERE id=?', (parcel_id,)
    elif user['role'] == 'seller':
        query, params = 'SELECT * FROM parcels WHERE id=? AND seller_id=?', (parcel_id, user['id'])
    else:
        query, params = 'SELECT * FROM parcels WHERE id=? AND rider_id=?', (parcel_id, user['id'])
    row = conn.execute(query, params).fetchone()
    if row is None:
        bad('Parcel not found.', 404)
    return row


def parcel_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in ('id','tracking_number','seller_id','rider_id','recipient_name',
                               'recipient_phone','recipient_address','weight_grams','status','created_at','updated_at')}
)
TRACK_RE = re.compile(r'^PT-[A-F0-9]{24}$')
STATUSES = ('Registered', 'Assigned', 'Out for Delivery', 'Delivered', 'Failed')
LOG = logging.getLogger('parceltrack')


def load_environment() -> None:
    """Read KEY=value from private project-root .env, keeping real env authoritative."""
    file = ROOT / '.env'
    if not file.is_file():
        return
    for line in file.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        if re.fullmatch(r'[A-Z][A-Z0-9_]*', k.strip()):
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def db_connection(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 10000')
    return conn


def db(request: Request):
    conn = db_connection(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('seller','rider','admin')),
 is_active INTEGER NOT NULL DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0,
 locked_until INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS parcels (
 id INTEGER PRIMARY KEY, tracking_number TEXT NOT NULL UNIQUE,
 seller_id INTEGER NOT NULL REFERENCES users(id), rider_id INTEGER REFERENCES users(id),
 recipient_name TEXT NOT NULL, recipient_phone TEXT NOT NULL,
 recipient_address TEXT NOT NULL, weight_grams INTEGER NOT NULL CHECK(weight_grams > 0),
 status TEXT NOT NULL CHECK(status IN ('Registered','Assigned','Out for Delivery','Delivered','Failed')),
 proof_path TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT
);
CREATE INDEX IF NOT EXISTS parcels_seller_idx ON parcels(seller_id);
CREATE INDEX IF NOT EXISTS parcels_rider_idx ON parcels(rider_id);
CREATE TABLE IF NOT EXISTS status_history (
 id INTEGER PRIMARY KEY, parcel_id INTEGER NOT NULL REFERENCES parcels(id) ON DELETE CASCADE,
 status TEXT NOT NULL, actor_user_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_parcel_idx ON status_history(parcel_id);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY, actor_user_id INTEGER REFERENCES users(id),
 event TEXT NOT NULL, entity_id INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
 rate_key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL
);
'''


def initialize(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = db_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def bad(message: str, code: int = 400) -> None:
    raise HTTPException(status_code=code, detail=message)


def text_value(value: Any, field: str, min_len: int, max_len: int) -> str:
    if not isinstance(value, str):
        bad(f'{field} is invalid.')
    value = value.strip()
    if not (min_len <= len(value) <= max_len) or any(ord(ch) < 32 for ch in value):
        bad(f'{field} must have {min_len}-{max_len} characters.')
    return value


def valid_email(value: Any) -> str:
    value = text_value(value, 'Email', 3, 254).lower()
    if not EMAIL_RE.fullmatch(value):
        bad('Email format is invalid.')
    return value


def valid_password(value: Any) -> str:
    if not isinstance(value, str) or not (10 <= len(value) <= 128):
        bad('Password must be 10-128 characters.')
    return value


def valid_phone(value: Any) -> str:
    value = text_value(value, 'Phone', 8, 20)
    if not PHONE_RE.fullmatch(value) or not (8 <= sum(ch.isdigit() for ch in value) <= 15):
        bad('Phone number format is invalid.')
    return value


def audit(conn: sqlite3.Connection, event: str, user_id: int | None, entity_id: int | None = None) -> None:
    conn.execute('INSERT INTO audit_logs(actor_user_id,event,entity_id,created_at) VALUES(?,?,?,?)',
                 (user_id, event, entity_id, utc_now()))


def client_ip(request: Request) -> str:
    # Accepted only after a shared-secret check, and the API only listens on loopback.
    ip = request.headers.get('X-Client-IP', '') if request.app.state.test_mode or request.client and request.client.host in ('127.0.0.1', '::1', 'testclient') else ''
    if not ip:
        ip = request.client.host if request.client else 'unknown'
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return 'unknown'


def throttle(conn: sqlite3.Connection, name: str, client: str, limit: int, window: int) -> None:
    # Hash the identifier so IP addresses/emails are not stored in this table.
    key = hashlib.sha256(f'{name}|{client}'.encode()).hexdigest()
    now = int(time.time())
    with conn:
        row = conn.execute('SELECT window_start,count FROM rate_limits WHERE rate_key=?', (key,)).fetchone()
        if row is None or now - row['window_start'] >= window:
            conn.execute('INSERT INTO rate_limits(rate_key,window_start,count) VALUES(?,?,1) '
                         'ON CONFLICT(rate_key) DO UPDATE SET window_start=excluded.window_start,count=1',
                         (key, now))
        elif row['count'] >= limit:
            bad('Too many requests. Please try again later.', 429)
        else:
            conn.execute('UPDATE rate_limits SET count=count+1 WHERE rate_key=?', (key,))


def issue_token(conn: sqlite3.Connection, uid: int) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn.execute('INSERT INTO sessions(token_hash,user_id,created_at,last_seen,expires_at) VALUES(?,?,?,?,?)',
                 (hashlib.sha256(token.encode()).hexdigest(), uid, now, now, now + 12 * 3600))
    return token


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def current_user(request: Request, conn: sqlite3.Connection = Depends(db)) -> dict:
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer ') or len(header) > 256:
        bad('Authentication required.', 401)
    token = header[7:]
    row = conn.execute('''SELECT u.id,u.name,u.email,u.role,u.is_active,s.last_seen,s.expires_at
                          FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?''',
                       (token_hash(token),)).fetchone()
    now = int(time.time())
    if not row or not row['is_active'] or row['expires_at'] <= now or now-row['last_seen'] > 30 * 60:
        bad('Session expired. Please log in again.', 401)
    conn.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?', (now, token_hash(token)))
    conn.commit()
    return dict(row)


def role_guard(*roles: str):
    def check(user: dict = Depends(current_user)) -> dict:
        if user['role'] not in roles:
            bad('Access denied.', 403)
        return user
    return check


def parcel_access(conn: sqlite3.Connection, parcel_id: int, user: dict) -> sqlite3.Row:
    if user['role'] == 'admin':
        query, params = 'SELECT * FROM parcels WHERE id=?', (parcel_id,)
    elif user['role'] == 'seller':
        query, params = 'SELECT * FROM parcels WHERE id=? AND seller_id=?', (parcel_id, user['id'])
    else:
        query, params = 'SELECT * FROM parcels WHERE id=? AND rider_id=?', (parcel_id, user['id'])
    row = conn.execute(query, params).fetchone()
    if row is None:
        bad('Parcel not found.', 404)
    return row


def parcel_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in ('id','tracking_number','seller_id','rider_id','recipient_name',
                               'recipient_phone','recipient_address','weight_grams','status','created_at','updated_at')}
