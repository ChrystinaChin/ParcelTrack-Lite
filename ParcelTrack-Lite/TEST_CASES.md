# ParcelTrack Lite — Security test cases

**Project:** STTCK3033 · Three-member case study. **Test environment:** Python FastAPI TestClient, temporary isolated SQLite DB, generated fictional identities and image samples. **Test command:** `python -m pytest -q`. **Owners:** each member must fill in their name/matric number and personally execute and document their module tests.

Owner M1: __________________ · Matric #: ________________

Owner M2: __________________ · Matric #: ________________

Owner M3: __________________ · Matric #: ________________

## Member 1 — Login and User Management

| ID | Input / test case | Expected result | Automated actual result |
|---|---|---|---|
| M1-01 | New seller / valid details and 10+ character password | Account created, role seller | PASS — seller registration |
| M1-02 | `short` as registration password | HTTP 400; no new account | PASS |
| M1-03 | SQL payload `' OR 1=1 --` in login email | Login denied; no SQL execution | PASS |
| M1-04 | Repeated wrong password 5 times then correct password | Account remains locked, HTTP 401 | PASS |
| M1-05 | Seller requests `/admin/dashboard` | HTTP 403 | PASS |
| M1-06 | Admin creates Rider | Account created with rider role | PASS |
| M1-07 | Admin disables Rider already logged in | Previous session denied, HTTP 401 | PASS |
| M1-08 | Password changed while logged in | Previous session revoked | PASS |
| M1-09 | Password stored in SQLite | Argon2 hash, no plaintext | PASS |
| M1-10 | Login without internal API key | HTTP 403 | PASS |
| M1-11 | Logout then reuse same token | HTTP 401 | PASS |

## Member 2 — Parcel Registration and Public Tracking

| ID | Input / test case | Expected result | Automated actual result |
|---|---|---|---|
| M2-01 | Normal parcel name, phone, address, weight `1.250` | Registered; unique random tracking ID | PASS |
| M2-02 | Recipient name `<script>alert(1)</script>` | Stored as data; PHP escapes when displayed | PASS API storage; browser rendering requires manual check |
| M2-03 | Seller B modifies URL to Seller A parcel ID | HTTP 404, no private data | PASS |
| M2-04 | Search `' OR 1=1 --` | No unauthorized results | PASS |
| M2-05 | Malformed phone `abc123` | HTTP 400 | PASS |
| M2-06 | Weight `-5` and nonnumeric `1 OR 1=1` | HTTP 400 | PASS |
| M2-07 | Address longer than 250 characters | HTTP 400 | PASS |
| M2-08 | Public lookup by correct tracking ID | Status and timestamps only, no PII | PASS |
| M2-09 | Wrong-format / SQL injection tracking ID | Generic HTTP 404 | PASS |
| M2-10 | 21 public tracking queries from same IP in 60 sec | HTTP 429 for query #21 | PASS |

## Member 3 — Delivery Update and Admin Dashboard

| ID | Input / test case | Expected result | Automated actual result |
|---|---|---|---|
| M3-01 | Seller/Rider calls admin-only assignment | HTTP 403 | PASS |
| M3-02 | Admin assigns parcel to active rider | Status Assigned, rider ID saved | PASS |
| M3-03 | Rider accesses parcel assigned to someone else | HTTP 404 | PASS |
| M3-04 | Rider updates parcel not assigned to them | HTTP 404 | PASS |
| M3-05 | Invalid status `Alien Status` | HTTP 400 | PASS |
| M3-06 | Skip Assigned → Delivered | HTTP 409 | PASS |
| M3-07 | Delivered without proof photo | HTTP 400 | PASS |
| M3-08 | Upload `shell.php.jpg` or fake PHP disguised as JPG | Rejected, HTTP 400 | PASS |
| M3-09 | Oversized photo >3MB | HTTP 413 | PASS |
| M3-10 | Valid PNG + Delivered update | Success; proof restricted to authorized users | PASS |
| M3-11 | Admin dashboard as Rider | HTTP 403 | PASS |
| M3-12 | Status history and audit records | Registered → Assigned → Out for Delivery → Delivered, actor/timestamp logged | PASS |
| M3-13 | Delivered parcel closed 13 months ago, run retention CLI | Recipient anonymized, private photo deleted | PASS |

## Manual demonstration records (fill in for grading)

| Module | Owner name | Browser/server test input | Expected result | Actual result | Date |
|---|---|---|---|---|---|
| M1 | | CSRF field removed from login POST | HTTP 403 | | |
| M1 | | `<script>` entered in name field | Escaped text shown | | |
| M2 | | `<script>alert(1)</script>` recipient name | Displayed literally, no alert | | |
| M2 | | Change `id` in parcel URL | No other Seller parcel data | | |
| M3 | | Upload `proof.php` through Rider browser | Upload rejected | | |
| M3 | | Submit valid photo and view Admin dashboard | Counts updated | | |

### Verified browser-to-database smoke checks (5 November 2026)

- PHP Seller registration, login and parcel creation — PASS.
- PHP output escaping for stored `<script>alert(1)</script>` — PASS (shown as `&lt;script&gt;`).
- PHP POST without CSRF token — PASS (HTTP 403).
- Public tracking with tracking number — PASS; address not present.
- Admin creates Rider, assigns parcel, Rider updates to Out for Delivery and then Delivered with PNG proof, Admin dashboard updates, Seller downloads authorized proof — PASS.

**Important:** Automated PASS means the corresponding FastAPI security test passed locally; it does not assert that every browser or server deployment scenario was tested. Fill manual actual results and member names before submission.
