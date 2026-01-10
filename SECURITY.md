# Security Documentation

## Encryption & Key Management

### Overview

This application uses **AES-256-CBC** encryption to protect sensitive data:
- 2FA TOTP secrets
- Recovery codes
- Webhook URLs

### Environment Variables

#### `JWT_SECRET` (Required)
- **Purpose**: Used for JWT token signing and authentication
- **Format**: Random string, minimum 32 characters recommended
- **Security**: Keep this secret and never commit to version control

#### `ENCRYPTION_KEY` (Optional, Recommended)
- **Purpose**: Used for encrypting sensitive data in the database
- **Default**: Falls back to `JWT_SECRET` if not provided (for backward compatibility)
- **Format**: Random string, minimum 32 characters recommended
- **Security**: Should be different from `JWT_SECRET` for defense in depth

### Why Separate Keys?

Having separate keys for JWT and encryption provides:

1. **Independence**: You can rotate JWT tokens without re-encrypting database
2. **Security**: If JWT_SECRET is compromised, encrypted data remains safe
3. **Compliance**: Meets best practices for key separation

### Setup Instructions

#### For Existing Installations

If you're upgrading from a version without `ENCRYPTION_KEY`:

**DO NOT CHANGE JWT_SECRET YET!** Existing encrypted data uses JWT_SECRET.

1. Set `ENCRYPTION_KEY` to your current `JWT_SECRET` value:
   ```bash
   ENCRYPTION_KEY="your-current-jwt-secret-value"
   ```

2. This maintains backward compatibility - all existing data will decrypt correctly

3. Once set, you can safely change `JWT_SECRET` if needed:
   ```bash
   JWT_SECRET="new-random-value-for-jwt-only"
   ```

#### For New Installations

Generate two separate random keys:

```bash
# Generate JWT_SECRET
openssl rand -base64 32

# Generate ENCRYPTION_KEY
openssl rand -base64 32
```

Add to your `.env` file:
```env
JWT_SECRET="generated-jwt-secret-here"
ENCRYPTION_KEY="generated-encryption-key-here"
```

### Key Rotation

#### Rotating JWT_SECRET

Safe to rotate at any time (users will need to re-login):

```bash
# 1. Generate new secret
NEW_JWT_SECRET=$(openssl rand -base64 32)

# 2. Update .env
JWT_SECRET="$NEW_JWT_SECRET"

# 3. Restart application
docker-compose restart backend
```

#### Rotating ENCRYPTION_KEY

⚠️ **WARNING**: Rotating ENCRYPTION_KEY requires re-encrypting ALL data!

This is a complex operation. Contact a developer before attempting.

### Audit Trail

All 2FA events are logged in the `audit_log` table:

- `2fa_enabled` - When user enables 2FA
- `2fa_disabled` - When user disables 2FA  
- `2fa_recovery_code_used` - When a recovery code is used for login

Each log entry includes:
- User ID
- Event type
- Timestamp
- IP address
- User agent
- Additional event data (JSON)

### Database Migrations

The application automatically handles:

1. **Migration 1**: Add initial 2FA columns
2. **Migration 2**: Add encrypted columns, encrypt existing data
3. **Migration 3**: Add stattrak/souvenir filters
4. **Migration 4**: Drop legacy plaintext columns (security cleanup)
5. **Migration 5**: Create audit_log table

### Security Best Practices

✅ **DO**:
- Use strong random keys (32+ characters)
- Keep `ENCRYPTION_KEY` separate from `JWT_SECRET`
- Backup your `.env` file securely
- Review audit logs regularly
- Use environment variables, never hardcode secrets

❌ **DON'T**:
- Never commit `.env` to version control
- Don't share keys via email or chat
- Don't use the same key for multiple environments
- Don't change `ENCRYPTION_KEY` without migration plan

### Recovery Procedures

#### Lost ENCRYPTION_KEY

If `ENCRYPTION_KEY` is lost, you **CANNOT** recover encrypted data.

Users will need to:
1. Disable 2FA (requires password)
2. Re-enable 2FA with new setup

#### Lost JWT_SECRET

Users will need to:
1. Re-login to get new JWT tokens
2. 2FA data remains intact (uses ENCRYPTION_KEY)

### Encryption Implementation

- **Algorithm**: AES-256-CBC
- **IV**: 16 random bytes per encryption (crypto.randomBytes)
- **Key Derivation**: SHA-256 hash of ENCRYPTION_KEY
- **Format**: `IV:ciphertext` (hex-encoded)
- **IV Length**: 32 hex characters (16 bytes)
- **Ciphertext**: Variable length depending on data

### Compliance Notes

- **GDPR**: Encryption protects user data at rest
- **SOC 2**: Audit trail tracks all security events
- **PCI DSS**: Key separation and strong encryption algorithms
- **HIPAA**: Encrypted data storage meets security requirements

## Questions?

For security-related questions or to report vulnerabilities, contact the development team.
