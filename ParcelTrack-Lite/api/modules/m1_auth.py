"""Member 1: authentication, self-registration, user management."""
import hmac
import secrets
import sqlite3
import time
from argon2.exceptions import VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from api.core import (DUMMY_PASSWORD_HASH, PH, audit, bad, client_ip, current_user,
                      db, issue_token, role_guard, text_value, throttle, token_hash,
                      utc_now, valid_email, valid_password)

router = APIRouter(prefix='/auth', tags=['M1: Authentication and Users'])

class UserRegistration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str
    email: str
    password: str

class Login(BaseModel):
    model_config = ConfigDict(extra='forbid')
    email: str
    password: str

class PasswordChange(BaseModel):
    model_config = ConfigDict(extra='forbid')
    current_password: str
    new_password: str


def create_user(conn, payload: UserRegistration, role: str) -> int:
    name = text_value(payload.name, 'Name', 2, 100)
    email = valid_email(payload.email)
    password = valid_password(payload.password)
    try:
        with conn:
            cur = conn.execute('''INSERT INTO users(name,email,password_hash,role,created_at)
                                  VALUES(?,?,?,?,?)''',
                               (name, email, PH.hash(password), role, utc_now()))
            audit(conn, 'user_created', cur.lastrowid, cur.lastrowid)
        return cur.lastrowid
    except sqlite3.IntegrityError:
        bad('Unable to create account with these details.', 409)


@router.post('/register', status_code=201)
def register(payload: UserRegistration, request: Request, conn=Depends(db)):
    throttle(conn, 'registration', client_ip(request), 5, 3600)
    return {'user_id': create_user(conn, payload, 'seller'), 'message': 'Account created.'}


@router.post('/login')
def login(payload: Login, request: Request, conn=Depends(db)):
    ip = client_ip(request)
    throttle(conn, 'login-ip', ip, 20, 900)
    email = valid_email(payload.email)
    throttle(conn, 'login-email', email, 10, 900)
    password = payload.password
    if not isinstance(password, str) or len(password) > 128:
        bad('Incorrect email or password.', 401)
    row = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    try:
        verified = PH.verify(row['password_hash'] if row else DUMMY_PASSWORD_HASH, password)
    except (VerifyMismatchError, VerificationError):
        verified = False
    now = int(time.time())
    if not row or not row['is_active'] or row['locked_until'] > now or not verified:
        with conn:
            if row and row['is_active'] and row['locked_until'] <= now:
                failed = (0 if row['locked_until'] and row['locked_until'] <= now else row['failed_attempts']) + 1
                locked_until = now + 900 if failed >= 5 else 0
                conn.execute('UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?',
                             (failed, locked_until, row['id']))
            audit(conn, 'login_failed', row['id'] if row else None)
        bad('Incorrect email or password.', 401)
    with conn:
        conn.execute('UPDATE users SET failed_attempts=0,locked_until=0 WHERE id=?', (row['id'],))
        token = issue_token(conn, row['id'])
        audit(conn, 'login_success', row['id'])
    return {'token': token, 'user': {'id': row['id'], 'name': row['name'], 'role': row['role'], 'email': row['email']}}


@router.get('/me')
def me(user=Depends(current_user)):
    return {'user': {k: user[k] for k in ('id','name','role','email')}}


@router.post('/logout')
def logout(request: Request, user=Depends(current_user), conn=Depends(db)):
    token = request.headers['Authorization'][7:]
    with conn:
        conn.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(token),))
        audit(conn, 'logout', user['id'])
    return {'message': 'Logged out.'}


@router.post('/change-password')
def change_password(payload: PasswordChange, user=Depends(current_user), conn=Depends(db)):
    new = valid_password(payload.new_password)
    row = conn.execute('SELECT password_hash FROM users WHERE id=?', (user['id'],)).fetchone()
    try:
        ok = PH.verify(row['password_hash'], payload.current_password)
    except (VerificationError, VerifyMismatchError):
        ok = False
    if not ok:
        bad('Current password is incorrect.', 400)
    if new == payload.current_password:
        bad('New password must be different.', 400)
    with conn:
        conn.execute('UPDATE users SET password_hash=? WHERE id=?', (PH.hash(new), user['id']))
        conn.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
        audit(conn, 'password_changed', user['id'])
    return {'message': 'Password updated. Please sign in again.'}


@router.get('/riders')
def riders(user=Depends(role_guard('admin')), conn=Depends(db)):
    records = conn.execute('SELECT id,name,email,is_active FROM users WHERE role=? ORDER BY id DESC',
                           ('rider',)).fetchall()
    return {'riders': [dict(row) for row in records]}


@router.post('/riders', status_code=201)
def create_rider(payload: UserRegistration, user=Depends(role_guard('admin')), conn=Depends(db)):
    rid = create_user(conn, payload, 'rider')
    with conn:
        audit(conn, 'rider_created_by_admin', user['id'], rid)
    return {'user_id': rid, 'message': 'Rider account created.'}


@router.post('/riders/{rider_id}/disable')
def disable_rider(rider_id: int, user=Depends(role_guard('admin')), conn=Depends(db)):
    with conn:
        cur = conn.execute('UPDATE users SET is_active=0 WHERE id=? AND role=? AND is_active=1',
                           (rider_id, 'rider'))
        if cur.rowcount == 0:
            bad('Rider not found or already disabled.', 404)
        conn.execute('DELETE FROM sessions WHERE user_id=?', (rider_id,))
        audit(conn, 'rider_disabled', user['id'], rider_id)
    return {'message': 'Rider account disabled.'}
