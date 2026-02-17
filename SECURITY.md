# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please DO NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it privately:

1. **Email:** [admin@oswaaaald.be](mailto:admin@oswaaaald.be)
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Initial response:** Within 48 hours
- **Status update:** Within 7 days
- **Fix timeline:** Depends on severity (critical: 7 days, high: 14 days, medium: 30 days)

### Disclosure Policy

- Security issues will be fixed before public disclosure
- Credit will be given to reporters (unless anonymity requested)
- CVE assignment for critical vulnerabilities

## Security Architecture

### Authentication

| Layer | Implementation |
|-------|---------------|
| **Password hashing** | bcrypt (12 rounds) with timing-safe comparison |
| **Password strength** | zxcvbn (score ≥ 3 required) |
| **JWT tokens** | Separate signing keys for access (10min) and refresh (14d) tokens |
| **Token rotation** | Automatic access/refresh token rotation with JTI tracking |
| **Token blacklisting** | Access tokens blacklisted on logout/password change |
| **TOTP 2FA** | otplib with encrypted secrets (AES-256-GCM), 10 recovery codes |
| **WebAuthn/Passkeys** | FIDO2 compliant (discoverable + non-discoverable credentials) |
| **OAuth2** | Google (PKCE), Discord (PKCE), GitHub — with encrypted state cookies |
| **Session invalidation** | All refresh tokens revoked + access token blacklisted on password change |
| **Timing-attack prevention** | Fake bcrypt hash comparison on non-existent users |

### Authorization

| Layer | Implementation |
|-------|---------------|
| **RBAC** | Three-tier: user → admin → super admin |
| **Route protection** | Per-route middleware with role verification |
| **Account restrictions** | Temporary (auto-expiry) + permanent bans with email blocking |
| **User approval** | New accounts require admin approval (first user auto-approved as super admin) |

### Data Protection

| Layer | Implementation |
|-------|---------------|
| **Encryption at rest** | AES-256-GCM for webhooks, TOTP secrets, recovery codes |
| **Separate encryption key** | `ENCRYPTION_KEY` independent from JWT secrets |
| **SQL injection** | Drizzle ORM parameterized queries + foreign key constraints |
| **XSS prevention** | Zod input validation on all endpoints + React output encoding |
| **CSRF protection** | Double-submit cookie pattern with constant-time comparison |
| **CORS** | Strict origin validation (single allowed origin) |
| **SSRF protection** | Webhook URL validation: domain whitelist, DNS resolution check, private IP blocking |
| **Avatar security** | Magic-byte validation, sharp re-encoding to WebP, EXIF stripping, random filenames, atomic writes |

### Infrastructure Security

| Layer | Implementation |
|-------|---------------|
| **Security headers** | Helmet (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) |
| **Rate limiting** | Global per-IP (configurable) + strict per-route (5 req/min for auth endpoints) |
| **Docker hardening** | Read-only filesystem, non-root user (1001), cap_drop ALL, no-new-privileges, tmpfs /tmp |
| **Network isolation** | Internal Docker network, PostgreSQL not exposed externally |
| **Health checks** | Lightweight database connectivity check at `/api/health` |
| **Graceful shutdown** | SIGTERM/SIGINT handlers with connection draining |
| **Cloudflare support** | `trustProxy: 1`, CF-Connecting-IP header extraction |

### Audit & Compliance

| Layer | Implementation |
|-------|---------------|
| **Security audit logs** | All auth events logged with IP + user agent (GDPR-compliant retention) |
| **Admin action logs** | Separate table tracking all administrative actions with admin attribution |
| **GDPR data export** | Full Art. 20 data portability (all user data as JSON) |
| **Account self-deletion** | With identity verification (password + 2FA if enabled) |
| **Cookie consent** | Banner with explicit consent tracking |
| **Auto-cleanup** | Configurable retention periods for audit logs and alerts |

## Security Headers

The API automatically sets these headers via Helmet:

```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
X-XSS-Protection: 1; mode=block
```

## Deployment Best Practices

### 1. Generate Strong Secrets

```bash
# Each must be unique and ≥ 32 characters
openssl rand -base64 48  # JWT_SECRET
openssl rand -base64 48  # JWT_ACCESS_SECRET (recommended, falls back to JWT_SECRET)
openssl rand -base64 48  # JWT_REFRESH_SECRET (recommended, falls back to JWT_SECRET)
openssl rand -base64 48  # ENCRYPTION_KEY (MUST differ from JWT secrets)
```

### 2. Enable HTTPS

- Use a reverse proxy (Nginx, Caddy, Traefik) or Cloudflare
- Configure HSTS headers
- Use valid TLS certificates (Let's Encrypt)
- Set `SSL/TLS Full (Strict)` mode in Cloudflare

### 3. Restrict Database Access

- Never expose PostgreSQL port publicly (keep on internal Docker network)
- Use strong `POSTGRES_PASSWORD`
- Use Docker volumes with proper permissions
- Enable encrypted backups

### 4. Configure Cloudflare (Recommended)

- WAF rules enabled
- DDoS protection
- Bot management
- SSL/TLS Full (Strict) mode

### Environment Variables

**NEVER commit these to Git:**
- `JWT_SECRET`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
- `ENCRYPTION_KEY`
- `SB_API_KEY`
- `POSTGRES_PASSWORD`
- OAuth client secrets (`GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_SECRET`, `DISCORD_CLIENT_SECRET`)
- Any `.env` file (except `.env.example`)

## Dependencies

- Automated dependency scanning via `npm audit`
- Regular updates for security patches
- Zero known vulnerabilities (as of Feb 2026)

## Contact

For security issues, email: [admin@oswaaaald.be](mailto:admin@oswaaaald.be)
