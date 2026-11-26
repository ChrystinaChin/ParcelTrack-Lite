# ParcelTrack Lite — Security implementation and review notes

## Trust boundaries

- **Public:** PHP's `php/public/` only; all visitors can use the public tracking form. PHP runs with per-request CSRF verification and output encoding.
- **Internal:** FastAPI only listens on `127.0.0.1` and rejects non-loopback traffic plus requests without `PARCELTRACK_INTERNAL_KEY`. This is a defense-in-depth safeguard, not a substitute for the network binding.
- **Private:** SQLite DB, `.env`, logs and image uploads lie outside the web root and are excluded from Git.

## Controls by rubric theme

| Control | Implementation | Recommended adversarial demonstration |
|---|---|---|
| SQL injection | All SQL values use SQLite `?` placeholders. | Search `' OR 1=1 --` / submit malformed login email; no extra records. |
| XSS | `h()` calls `htmlspecialchars(... ENT_QUOTES ...)` for display values; CSP `script-src` falls back to `default-src 'none'`. | Enter `<script>alert(1)</script>` in recipient name; it is displayed as text, not executed. |
| IDOR / role access | `role_guard()`, `parcel_access()` in Python on every call. | Change Seller/Rider parcel ID; API returns 404. Seller requests dashboard; 403. |
| Brute force | 5 failed logins lock account 15 min; email and IP request throttles. | Wrong password five times; correct password still rejected until lock expiry. |
| Password | Argon2id `PasswordHasher`, min 10 characters; no plaintext storage. | Inspect `users.password_hash` and weak password rejection. |
| Authentication sessions | Secure PHP session cookie configuration and `session_regenerate_id`; random API bearer token stored only in PHP session and hashed in SQLite. | Logout/change password invalidates bearer token in API. |
| CSRF | Unpredictable synchronized PHP session CSRF token on every POST. | Remove `csrf` form field; HTTP 403. |
| Public tracking | Random 96-bit token `PT-` + 24 hex digits, generic 404, 20/min per IP. | Guess tracking ID, script/SQL payload and request flooding. |
| Personal data | No private fields in public JSON, owner/assignment checks in private requests. | Compare `/public/track/` vs authorized `/parcels/{id}`. |
| Upload safety | JPG/PNG extension format and real content validated; image re-encoded; <=3MB; <=10M pixels; random 0600 file outside webroot. | `shell.php.jpg`, fake `.jpg`, oversized photo and `.php` payload are rejected. |
| State transitions | Assigned → Out for Delivery → Delivered or Failed; photo required for final result. | Submit unexpected status or skip a state. |
| Audit | `audit_logs` records actor ID/event/entity/timestamp; no passwords or address. | Check `login_failed`, `rider_assigned`, `status_delivered`. |
| Secure errors | HTTP 400/401/403/404/409/413/429/422 and generic 500/503 errors, details in server logs. | Wrong input, missing parcel, unauthorized access, missing backend. |
| Retention | `python -m api.cli anonymize` removes personal fields + proofs 12 calendar months after terminal outcome. | Run via scheduled job and verify old synthetic records. |

## Operational constraints

**Do not expose the API or private folders over the Internet.** The shared API secret must be randomly generated per environment. In development the PHP and Python servers are loopback-only. In production use HTTPS end to end for browsers, a trusted public web server + PHP-FPM, and a private API bound to loopback. Protect backups and restricted system file permissions; ensure production log access is limited.

**Rate limits:** they are recorded in SQLite by hashed IP/identifier. One IP shared by many users may be rate-limited as a group; choose careful trusted-proxy IP handling. **Database size:** the list endpoints return 200 rows; production pagination would be appropriate at larger volume. **Proof photos:** decoding and re-encoding is defense-in-depth, not a guarantee that every malicious file is safe. Add scanning if serving real customer uploads.

**Account handling:** Sellers self-register, but Rider and Admin roles cannot be self-assigned. Only CLI creates Admins, and only Admins create/disable Riders. Admin accounts are not seeded with passwords.

**Monitoring/incident:** suspicious activity requires manual operational review. The case study's breach-response timelines are organizational procedures; software logs support investigation but do not automate reporting. Add incident escalation and MFA for production.

## Responsible collaboration

GitHub must not contain actual customer data, active secrets, database backups or uploaded photos. `.gitignore` protects common accidental commits but cannot undo secrets already committed. If accidentally pushed, rotate the key and remove the secret from Git history. Do not add real customer data to automated tests.
