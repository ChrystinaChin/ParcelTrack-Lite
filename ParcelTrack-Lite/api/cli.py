"""Create admin account and run 12-month personal-data anonymization."""
import argparse
import getpass
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from dateutil.relativedelta import relativedelta
from api.core import (PH, ROOT, audit, db_connection, initialize, load_environment,
                      text_value, utc_now, valid_email, valid_password)


def prompt_admin_password() -> str:
    """Reprompt instead of exposing an exception traceback for bad input."""
    while True:
        candidate = getpass.getpass('Admin password (12+ characters): ')
        try:
            valid_password(candidate)
        except HTTPException as exc:
            print(f'Password rejected: {exc.detail}')
            continue
        confirmation = getpass.getpass('Confirm admin password: ')
        if candidate != confirmation:
            print('Passwords do not match. Please try again.')
            continue
        return candidate


def main():
    parser = argparse.ArgumentParser(description='ParcelTrack maintenance tools')
    parser.add_argument('command',choices=['init-db','create-admin','anonymize'])
    args = parser.parse_args()
    load_environment()
    path = os.environ.get('PARCELTRACK_DB_PATH',str(ROOT/'instance'/'parceltrack.sqlite3'))
    initialize(path)
    if args.command == 'init-db':
        print('Database initialized.')
        return
    conn = db_connection(path)
    try:
        if args.command == 'create-admin':
            name = text_value(input('Admin name: '),'Admin name',2,100)
            email = valid_email(input('Admin email: '))
            password = prompt_admin_password()
            with conn:
                cur = conn.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                                   (name,email,PH.hash(password),'admin',utc_now()))
                audit(conn,'admin_created',cur.lastrowid,cur.lastrowid)
            print('Admin created.')
        elif args.command == 'anonymize':
            # Calendar months, not a fixed day count; run daily via a server scheduler.
            cutoff = (datetime.now(timezone.utc)-relativedelta(months=12)).isoformat(timespec='seconds')
            with conn:
                conn.execute('DELETE FROM sessions WHERE expires_at < ? OR last_seen < ?',
                             (int(time.time()), int(time.time()) - 1800))
                conn.execute('DELETE FROM rate_limits WHERE window_start < ?',
                             (int(time.time()) - 86400 * 2,))
                rows = conn.execute('''SELECT id,proof_path FROM parcels
                                       WHERE closed_at IS NOT NULL AND closed_at <= ?
                                       AND status IN ('Delivered','Failed')
                                       AND recipient_name <> '[anonymized]' ''',(cutoff,)).fetchall()
                for row in rows:
                    conn.execute('''UPDATE parcels SET recipient_name='[anonymized]',
                       recipient_phone='[anonymized]',recipient_address='[anonymized]',
                       proof_path=NULL WHERE id=?''', (row['id'],))
                    audit(conn,'recipient_anonymized',None,row['id'])
            # Only unlink after DB commit; if file deletion fails, alert operators.
            for row in rows:
                if row['proof_path']:
                    Path(row['proof_path']).unlink(missing_ok=True)
            print(f'Anonymized {len(rows)} closed parcels.')
    finally:
        conn.close()

if __name__ == '__main__':
    main()
