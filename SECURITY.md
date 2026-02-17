# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ |
| Older versions | ❌ |

Only the latest version deployed from the `main` branch receives security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, **do not open a public issue**.

Please report vulnerabilities privately via:
- **Email:** [contact the repository owner via GitHub profile](https://github.com/Oswaaaald)
- **GitHub Security Advisories:** [Report a vulnerability](https://github.com/Oswaaaald/Skinbaron-tracker/security/advisories/new)

### What to include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline
- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix & disclosure:** coordinated with reporter

## Security Architecture

### Authentication
- **Passwords:** bcrypt (12 rounds) with zxcvbn strength validation (score ≥ 3)
- **JWT:** Separate signing keys for access tokens (`JWT_ACCESS_SECRET`) and refresh tokens (`JWT_REFRESH_SECRET`), with token rotation and JTI-based revocation
- **2FA:** TOTP (otplib) with encrypted secrets (AES-256-GCM), 10 recovery codes with constant-time comparison
- **Passkeys:** WebAuthn/FIDO2 via @simplewebauthn/server with single-use challenges stored in PostgreSQL
- **OAuth2:** Google, Discord, GitHub with PKCE; encrypted state/pending cookies; auto-links by verified email
- **Timing attacks:** Fake bcrypt hash for non-existent users; `timingSafeEqual` on all token/code comparisons

### Encryption
- **Algorithm:** AES-256-GCM with random 12-byte IV per encryption
- **Encrypted data:** Webhook URLs, TOTP secrets, recovery codes, OAuth state cookies
- **Key management:** `ENCRYPTION_KEY` required in production, must differ from `JWT_SECRET`

### Access Control
- **3-tier RBAC:** User → Admin → Super Admin
- **Middleware chain:** Rate limiting → CSRF → Auth → RBAC per route
- **Account restrictions:** Temporary (auto-expiry) and permanent with email banning
- **Restriction enforcement:** Checked at every auth flow (login, refresh, OAuth, passkey)

### Input Validation & Injection Prevention
- **Zod v4** schema validation on all route inputs (body, query, params)
- **Drizzle ORM** parameterized queries (no raw SQL interpolation)
- **SSRF protection:** Webhook URLs validated against domain allowlist, DNS resolution blocks private IPs (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)
- **Avatar upload:** Magic-byte validation, sharp re-encoding to WebP (strips EXIF, resizes to 256px), random filenames via `crypto.randomBytes`

### Transport & Cookie Security
- **Cookies:** `httpOnly`, `secure` (production), `sameSite: none` (cross-origin) / `lax` (dev), scoped `domain`
- **CORS:** Strict origin allowlist via `CORS_ORIGIN`
- **CSRF:** Double-submit cookie pattern with encrypted HMAC token and constant-time verification
- **Helmet:** Security headers (CSP, HSTS, X-Frame-Options, etc.)

### Infrastructure
- **Docker hardening:** Read-only filesystems, `cap_drop: ALL`, `no-new-privileges`, non-root user (UID 1001)
- **PostgreSQL:** Internal Docker network only (not exposed to host), optional SSL (`DATABASE_SSL`)
- **Rate limiting:** Per-IP, configurable globally and per-route (auth: 5/min, batch: 10/min, avatar: 3/5min)
- **Graceful shutdown:** SIGTERM/SIGINT handlers drain connections and stop scheduler

### Data Lifecycle
- **Audit logs:** Auto-cleanup after configurable retention (`AUDIT_LOG_RETENTION_DAYS`, default: 365)
- **Alerts:** Auto-cleanup after configurable retention (`ALERT_RETENTION_DAYS`, default: 90)
- **Refresh tokens:** Expired/revoked tokens cleaned up on each scheduler cycle
- **Access token blacklist:** Expired entries cleaned up on each scheduler cycle
- **Pending challenges:** TTL-based expiry with periodic cleanup (replaces in-memory Maps)
- **GDPR data export:** Users can download all personal data as JSON (Art. 20)
- **Account deletion:** Self-service with identity verification, cascade deletes all user data

## Known Considerations

- **Single-instance deployment:** The application is designed for single-instance Docker deployment behind a reverse proxy (e.g., Caddy, Traefik, Nginx). Session affinity is not required since all state is in PostgreSQL.
- **OAuth provider trust:** OAuth email linking trusts the `email_verified` claim from providers. This is industry-standard but means account security depends on the OAuth provider's email verification.
- **Rate limiting scope:** Rate limiting is per-IP. Behind a reverse proxy, ensure `X-Forwarded-For` / `X-Real-IP` headers are correctly set to avoid all traffic sharing one IP.
