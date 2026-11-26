# ParcelTrack Lite — Secure Parcel Tracking System

A working **three-member** course project for KirimCepat Sdn. Bhd., based on `ParcelTrack_case_study_3Members.docx`. The separately supplied *four-member* rubric is not the module allocation for this build.

**Stack:** Python 3.11+ / FastAPI API · SQLite database · PHP 8.2+ frontend · CSS · Git/GitHub.

## Features by member

| Member | Module files owned | Features |
|---|---|---|
| Member 1 | `api/modules/m1_auth.py`, `php/src/m1_pages.php` | Seller self-registration, login/logout, Argon2 passwords, password changes, admin creates/disables riders, server-side role authorization, lockout. |
| Member 2 | `api/modules/m2_parcels.py`, `php/src/m2_pages.php` | Seller parcel registration, unique cryptographic tracking numbers, own-only parcel details and search, privacy-preserving public tracking. |
| Member 3 | `api/modules/m3_delivery.py`, `php/src/m3_pages.php` | Admin assignment and dashboard, assigned-only rider deliveries, status history, JPG/PNG proof photos. |
| Shared | `api/core.py`, `api/factory.py`, `api/cli.py`, `php/src/bootstrap.php`, `php/public/index.php`, tests, docs | Shared SQLite, authentication bridge, PHP sessions, CSRF, tests, integration and deployments. |

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

## Walkthrough (suggested demo)

1. **Member 1:** Seller registers with password >=10 characters. Show login, logout, Admin creates Rider, weak-password rejection, failed-login lockout and Seller receiving HTTP 403 from an Admin-only endpoint.
2. **Member 2:** Seller registers a parcel, searches own tracking number, sees an unguessable `PT-` tracking number, fails to access another Seller's parcel, and demonstrates public tracking (history contains **only status/timestamp**).
3. **Member 3:** Admin assigns parcel, Rider sees only assigned parcels, changes Assigned → Out for Delivery → Delivered/Failed with verified JPG/PNG image, and Admin dashboard counts update. Show a rejected `.php`-extension upload and invalid status change.

The case study's final delivery status requires a single proof photo. This implementation also requires a photo for **Failed** outcomes (a conservative interpretation). JPG/PNG images are decoded and re-encoded; original filenames and image metadata are not retained.

## Running tests

```bash
python -m pip install pytest httpx
python -m pytest -q
```

PHP validation:

```bash
find php -name '*.php' -print0 | xargs -0 -n1 php -l  # Linux/macOS
```

For Windows, run `php -l php/public/index.php` and repeat for each file in `php/src/`. GitHub Actions automatically runs the Python tests and PHP lint on pull requests.

See [`SECURITY.md`](SECURITY.md) and [`TEST_CASES.md`](TEST_CASES.md) for security explanations and assessment evidence.

## GitHub collaboration

1. Create an **empty private GitHub repository** for the group; avoid uploading actual recipient information.
2. From this project root, run:

   ```bash
   git init
   git add .
   git commit -m "chore: scaffold secure ParcelTrack Lite app"
   git branch -M main
   git remote add origin https://github.com/YOUR-TEAM/parceltrack-lite.git
   git push -u origin main
   ```

3. Invite your two team members via GitHub **Settings → Collaborators**. Have each person use their own GitHub account and feature branch: `feature/m1-auth`, `feature/m2-parcels`, `feature/m3-delivery`.
4. Each member should **implement, modify, test and commit their assigned module themselves**. Create a Pull Request and request another member's review; merge after CI passes. The provided scaffold is a starting implementation, **not proof of who authored the work**. Your rubric uses actual commit history for individual ownership.
5. Do not commit `.env`, SQLite files, real recipient data, or uploaded images. Configure GitHub branch protection for `main`, require reviews and passing CI.

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
