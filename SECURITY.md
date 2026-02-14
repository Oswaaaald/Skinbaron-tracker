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

## Security Best Practices

### Deployment

1. **Always use strong secrets:**
   ```bash
   # Generate with:
   openssl rand -base64 48
   ```

2. **Enable HTTPS in production:**
   - Use reverse proxy (Nginx, Caddy, Traefik)
   - Configure HSTS headers
   - Use valid TLS certificates (Let's Encrypt)

3. **Restrict database access:**
   - Never expose PostgreSQL port publicly (keep it on the internal Docker network)
   - Use strong `POSTGRES_PASSWORD` for the database
   - Use Docker volumes with proper permissions
   - Enable backups with encryption

4. **Configure Cloudflare (recommended):**
   - WAF rules enabled
   - DDoS protection
   - Bot management
   - SSL/TLS Full (Strict) mode

### Environment Variables

**NEVER commit these to Git:**
- `JWT_SECRET`
- `ENCRYPTION_KEY`
- `SB_API_KEY`
- Any `.env` file (except `.env.example`)

### Known Security Features

- ✅ JWT rotation with refresh tokens
- ✅ CSRF protection (double-submit cookie)
- ✅ Rate limiting (per-IP)
- ✅ AES-256-GCM encryption
- ✅ TOTP 2FA
- ✅ Helmet security headers
- ✅ CORS strict origin validation
- ✅ SQL injection prevention (Drizzle ORM parameterized queries)
- ✅ XSS protection (Zod validation + React escaping)
- ✅ Docker security hardening

## Security Headers

The API automatically sets these headers via Helmet:

```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000
X-XSS-Protection: 1; mode=block
```

## Dependencies

- Automated dependency scanning via `npm audit`
- Regular updates for security patches
- Zero known vulnerabilities (as of Feb 2026)

## Contact

For security issues, email: [admin@oswaaaald.be](mailto:admin@oswaaaald.be)
