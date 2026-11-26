"""Member 2: seller parcel management and public tracking."""
import re
import secrets
import sqlite3
from decimal import Decimal, InvalidOperation
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from api.core import (TRACK_RE, audit, bad, client_ip, current_user, db, parcel_access,
                      parcel_dict, role_guard, text_value, throttle, utc_now, valid_phone)

router = APIRouter(tags=['M2: Parcels and Public Tracking'])

class CreateParcel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    recipient_name: str
    recipient_phone: str
    recipient_address: str
    weight_kg: str


def weight_grams(raw) -> int:
    if not isinstance(raw, str) or not re.fullmatch(r'[0-9]{1,4}(?:\.[0-9]{1,3})?', raw):
        bad('Weight must be a positive number with up to three decimal places.')
    try:
        grams = int(Decimal(raw) * Decimal('1000'))
    except (InvalidOperation, ValueError):
        bad('Weight is invalid.')
    if not (1 <= grams <= 100_000):
        bad('Weight must be between 0.001 and 100 kg.')
    return grams


@router.post('/parcels', status_code=201)
def register_parcel(payload: CreateParcel, user=Depends(role_guard('seller')), conn=Depends(db)):
    name = text_value(payload.recipient_name, 'Recipient name', 2, 100)
    phone = valid_phone(payload.recipient_phone)
    address = text_value(payload.recipient_address, 'Address', 5, 250)
    grams = weight_grams(payload.weight_kg)
    now = utc_now()
    for _ in range(5):
        tracking = 'PT-' + secrets.token_hex(12).upper()
        try:
            with conn:
                cur = conn.execute('''INSERT INTO parcels(tracking_number,seller_id,recipient_name,
                     recipient_phone,recipient_address,weight_grams,status,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?)''',
                     (tracking,user['id'],name,phone,address,grams,'Registered',now,now))
                pid = cur.lastrowid
                conn.execute('INSERT INTO status_history(parcel_id,status,actor_user_id,created_at) VALUES(?,?,?,?)',
                             (pid,'Registered',user['id'],now))
                audit(conn, 'parcel_registered', user['id'], pid)
            return {'parcel_id': pid, 'tracking_number': tracking, 'message': 'Parcel registered.'}
        except sqlite3.IntegrityError:
            continue
    bad('Unable to generate tracking number. Please retry.', 503)


@router.get('/parcels')
def list_parcels(search: str = '', user=Depends(role_guard('seller')), conn=Depends(db)):
    if len(search) > 100:
        bad('Search is too long.')
    # Escape % and _ to avoid wildcard surprises. All values remain query parameters.
    match = '%' + search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
    rows = conn.execute('''SELECT * FROM parcels WHERE seller_id=?
                           AND tracking_number LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 200''',
                        (user['id'], match)).fetchall()
    return {'parcels': [parcel_dict(r) for r in rows]}


@router.get('/parcels/{parcel_id}')
def parcel_detail(parcel_id: int, user=Depends(current_user), conn=Depends(db)):
    parcel = parcel_access(conn, parcel_id, user)
    history = conn.execute('SELECT status,created_at FROM status_history WHERE parcel_id=? ORDER BY id',
                           (parcel_id,)).fetchall()
    return {'parcel': parcel_dict(parcel), 'history': [dict(row) for row in history],
            'has_proof': bool(parcel['proof_path'])}


@router.get('/public/track/{tracking}')
def public_track(tracking: str, request: Request, conn=Depends(db)):
    throttle(conn, 'tracking-ip', client_ip(request), 20, 60)
    if len(tracking) > 60 or not TRACK_RE.fullmatch(tracking):
        bad('Tracking number not found.', 404)
    row = conn.execute('SELECT id FROM parcels WHERE tracking_number=?', (tracking,)).fetchone()
    if row is None:
        bad('Tracking number not found.', 404)
    history = conn.execute('''SELECT status,created_at FROM status_history
                              WHERE parcel_id=? ORDER BY id''', (row['id'],)).fetchall()
    # Only status and timestamp: never send parcel IDs, people, addresses or phone numbers.
    return {'history': [dict(h) for h in history]}
