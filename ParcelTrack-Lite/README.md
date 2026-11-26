# ParcelTrack Lite — Secure Parcel Tracking System

A working course project for KirimCepat Sdn. Bhd., based on `ParcelTrack_case_study_3Members.docx`.

**Stack:** Python 3.11+ / FastAPI API · SQLite database · PHP 8.2+ frontend · CSS · Git/GitHub.

## Architecture

```
Browser --HTTPS in production--> PHP web UI (php/public/)
                                      | server-side requests
                                      | X-Internal-Key + user session token
                                      v
                             Python FastAPI 127.0.0.1:5000
                                      | parameterized SQL
                                      v
                              instance/parceltrack.sqlite3
                              instance/uploads/ (PRIVATE)
```

The PHP session stores the API's random session token **server-side**. It is not sent to browser JavaScript or shown in HTML. The Python API checks authenticated roles and record ownership independently. Python API must **never** be bound to a public IP address.

## Quick start — Windows (PowerShell)

Install Python 3.11+, PHP 8.2+ (e.g., via XAMPP/Laragon or standalone PHP) and Git. Enable PHP `allow_url_fopen` (enabled by default in typical PHP configurations).

```powershell
git clone https://github.com/YOUR-TEAM/parceltrack-lite.git
cd parceltrack-lite
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Open `.env` in a text editor. Paste the printed random value after `PARCELTRACK_INTERNAL_KEY=`. **Never commit `.env`.** The server refuses to start without a long secret.

Create the database and your *own* admin account (no default password):

```powershell
python -m api.cli init-db
python -m api.cli create-admin
```

Open **two terminals** in the repository root, with the Python virtual environment active in the first:

**Terminal 1 — Python API**

```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 5000
```

**Terminal 2 — PHP**

```powershell
php -d upload_max_filesize=4M -d post_max_size=4M -S 127.0.0.1:8080 -t php/public php/public/router.php
```

Open **http://127.0.0.1:8080**. You can sign up as a Seller, or use the Admin account created in the CLI to add Riders.

> XAMPP/Laragon option: configure the website's **document root** as `php/public`, not the repo root. Run the Python API separately and keep it bound to `127.0.0.1:5000`. Never serve `.env`, `instance/`, or `api/` as public files.

## Quick start — macOS or Linux

```bash
git clone https://github.com/YOUR-TEAM/parceltrack-lite.git
cd parceltrack-lite
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python -c 'import secrets; print(secrets.token_hex(32))'
# Paste into PARCELTRACK_INTERNAL_KEY= in .env
python -m api.cli init-db
python -m api.cli create-admin
python -m uvicorn api.main:app --host 127.0.0.1 --port 5000
# In another terminal:
php -d upload_max_filesize=4M -d post_max_size=4M -S 127.0.0.1:8080 -t php/public php/public/router.php
```

## Security and privacy notes

- Inbound requests to the API require the shared secret and loopback access. Backend role checks are authoritative; PHP navigation checks are just convenience.
- Session cookies: HttpOnly, Strict SameSite, Secure on HTTPS, regenerated on login and periodically; pre-auth and authenticated forms use CSRF tokens.
- SQLite uses `?` placeholders. User-controlled HTML is escaped with `htmlspecialchars`. A restrictive CSP disables scripts.
- Passwords are Argon2 hashed; sessions are random 256-bit tokens stored as SHA-256 digests in SQLite, expire after 12 hours / 30 minutes idle; new passwords revoke all sessions.
- Public tracking results contain only status history and timestamps; requests are rate-limited.
- Photos are validated as real images, restricted to JPG/PNG <=3 MB and <=10 million pixels, re-encoded and kept outside `php/public` with random filenames.
- Audit logs record events and user IDs but no passwords, recipient addresses or full payloads.
- **12-month retention:** run `python -m api.cli anonymize` **every day** using Windows Task Scheduler or cron. This anonymizes recipient details of terminal-state parcels and deletes associated photos. The project cannot enforce the deadline if the job is never scheduled.
- Only fictional test data should be used for assignment testing. Admin accounts are generated interactively; no credentials are bundled.

## Production considerations

This is a **local educational app**, not a third-party-audited production service. For deployment: run PHP behind Apache/Nginx and HTTPS with `PARCELTRACK_ENV=production`, run Uvicorn under a managed service bound to loopback, protect secrets and database backups, schedule retention cleanup, set server-side PHP upload size limits, and add operational monitoring. Do not use PHP's development server on the public Internet. Use a trusted reverse-proxy configuration for client IP handling (never trust arbitrary forwarded-IP headers). For real customers, add a proper deployment hardening review, dependency scanning, MFA for administrators, data-encryption/backup policy, and an independent penetration test.
