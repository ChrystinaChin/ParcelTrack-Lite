"""Member 3: admin assignment/dashboard and rider delivery/proof photo."""
import io
import os
import re
import secrets
from pathlib import Path
from PIL import Image, ImageOps, UnidentifiedImageError
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from api.core import (STATUSES, audit, bad, db, parcel_access, parcel_dict,
                      role_guard, utc_now)

router = APIRouter(tags=['M3: Delivery and Admin'])
MAX_PROOF_BYTES = 3 * 1024 * 1024
MAX_PIXELS = 10_000_000
Image.MAX_IMAGE_PIXELS = MAX_PIXELS
ALLOWED_NAMES = re.compile(r'^[A-Za-z0-9_-]{1,64}\.(?:jpg|jpeg|png)$', re.IGNORECASE)

class AssignParcel(BaseModel):
    model_config = ConfigDict(extra='forbid')
    rider_id: int


@router.get('/admin/dashboard')
def dashboard(user=Depends(role_guard('admin')), conn=Depends(db)):
    counts = {status: 0 for status in STATUSES}
    for row in conn.execute('SELECT status,COUNT(*) AS qty FROM parcels GROUP BY status'):
        counts[row['status']] = row['qty']
    return {'counts': counts, 'total': sum(counts.values())}


@router.get('/admin/parcels')
def admin_parcels(user=Depends(role_guard('admin')), conn=Depends(db)):
    rows = conn.execute('SELECT * FROM parcels ORDER BY id DESC LIMIT 200').fetchall()
    return {'parcels': [parcel_dict(row) for row in rows]}


@router.post('/admin/parcels/{parcel_id}/assign')
def assign(parcel_id: int, payload: AssignParcel,
           user=Depends(role_guard('admin')), conn=Depends(db)):
    rider = conn.execute('SELECT id FROM users WHERE id=? AND role=? AND is_active=1',
                         (payload.rider_id,'rider')).fetchone()
    if rider is None:
        bad('Active rider not found.', 404)
    with conn:
        parcel = conn.execute('SELECT id,status FROM parcels WHERE id=?', (parcel_id,)).fetchone()
        if not parcel:
            bad('Parcel not found.', 404)
        if parcel['status'] in ('Delivered', 'Failed'):
            bad('Completed parcels cannot be reassigned.', 409)
        new_status = 'Assigned' if parcel['status'] != 'Out for Delivery' else 'Out for Delivery'
        now = utc_now()
        conn.execute('UPDATE parcels SET rider_id=?,status=?,updated_at=? WHERE id=?',
                     (rider['id'], new_status, now, parcel_id))
        if parcel['status'] != new_status:
            conn.execute('INSERT INTO status_history(parcel_id,status,actor_user_id,created_at) VALUES(?,?,?,?)',
                         (parcel_id, new_status,user['id'],now))
        audit(conn, 'rider_assigned',user['id'],parcel_id)
    return {'message': 'Rider assigned.'}


@router.get('/rider/parcels')
def rider_parcels(user=Depends(role_guard('rider')), conn=Depends(db)):
    rows = conn.execute('SELECT * FROM parcels WHERE rider_id=? ORDER BY id DESC LIMIT 200',
                        (user['id'],)).fetchall()
    return {'parcels': [parcel_dict(row) for row in rows]}


def sanitize_photo(raw: bytes, filename: str) -> tuple[bytes, str]:
    if not isinstance(filename,str) or not ALLOWED_NAMES.fullmatch(filename):
        bad('Photo must have a single .jpg, .jpeg or .png extension.')
    if not raw or len(raw) > MAX_PROOF_BYTES:
        bad('Photo must be nonempty and at most 3 MB.', 413)
    try:
        with Image.open(io.BytesIO(raw)) as im:
            if im.format not in ('JPEG','PNG') or im.width * im.height > MAX_PIXELS:
                bad('Photo content is invalid or too large.')
            if (im.format == 'JPEG' and not filename.lower().endswith(('.jpg','.jpeg')) or (im.format == 'PNG' and not filename.lower().endswith('.png'))):
                bad('Photo extension does not match its contents.')
            im.verify()
        with Image.open(io.BytesIO(raw)) as im:
            im.load()
            im = ImageOps.exif_transpose(im)
            out = io.BytesIO()
            if im.format == 'PNG' or filename.lower().endswith('.png'):
                im.convert('RGBA' if 'A' in im.getbands() else 'RGB').save(out, format='PNG')
                suffix = '.png'
            else:
                im.convert('RGB').save(out,format='JPEG',quality=85)
                suffix = '.jpg'
            return out.getvalue(), suffix
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        bad('Photo is not a valid JPG or PNG image.')


@router.post('/rider/parcels/{parcel_id}/status')
async def update_status(parcel_id: int, request: Request, status: str = Form(...),
                        proof: UploadFile | None = File(None),
                        user=Depends(role_guard('rider')), conn=Depends(db)):
    if status not in ('Out for Delivery','Delivered','Failed'):
        bad('Invalid delivery status.')
    row = parcel_access(conn, parcel_id, user)
    legal = {'Assigned': ('Out for Delivery',),
             'Out for Delivery': ('Delivered','Failed')}
    if status not in legal.get(row['status'], ()):
        bad('Invalid status transition.', 409)
    final = status in ('Delivered', 'Failed')
    if final and proof is None:
        bad('A proof-of-delivery JPG or PNG photo is required.')
    if not final and proof is not None and proof.filename:
        bad('Only final delivery outcomes accept a photo.')
    saved_path = None
    if final:
        # Read no more than max+1; neither extension nor declared MIME is trusted.
        content = await proof.read(MAX_PROOF_BYTES + 1)
        clean, suffix = sanitize_photo(content, proof.filename or '')
        directory = Path(request.app.state.upload_dir)
        name = secrets.token_hex(24) + suffix
        saved_path = directory / name
        fd = os.open(saved_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(clean)
        except Exception:
            saved_path.unlink(missing_ok=True)
            raise
    try:
        with conn:
            # Compare state and assigned rider inside UPDATE to prevent stale decisions.
            now = utc_now()
            cur = conn.execute('''UPDATE parcels SET status=?,proof_path=?,updated_at=?,closed_at=?
                                  WHERE id=? AND rider_id=? AND status=?''',
                               (status, str(saved_path) if saved_path else row['proof_path'],now,
                                now if final else None, parcel_id, user['id'], row['status']))
            if cur.rowcount != 1:
                bad('Parcel assignment or status changed. Reload and try again.', 409)
            conn.execute('INSERT INTO status_history(parcel_id,status,actor_user_id,created_at) VALUES(?,?,?,?)',
                         (parcel_id,status,user['id'],now))
            audit(conn, 'status_'+status.lower().replace(' ','_'),user['id'],parcel_id)
    except Exception:
        if saved_path:
            saved_path.unlink(missing_ok=True)
        raise
    return {'message':'Delivery status updated.'}


@router.get('/parcels/{parcel_id}/proof')
def proof_file(parcel_id: int, user=Depends(role_guard('seller','rider','admin')),
               conn=Depends(db)):
    parcel = parcel_access(conn, parcel_id, user)
    if not parcel['proof_path']:
        bad('Proof photo not found.', 404)
    path = Path(parcel['proof_path'])
    if not path.is_file():
        bad('Proof photo unavailable.', 404)
    mime = 'image/png' if path.suffix == '.png' else 'image/jpeg'
    return FileResponse(path,media_type=mime,filename='delivery-proof'+path.suffix,
                        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
                                 'Content-Security-Policy':"default-src 'none'; sandbox"})
