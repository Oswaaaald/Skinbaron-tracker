import type { FastifyRequest } from 'fastify';
import { OTP } from 'otplib';
import crypto from 'crypto';
import type { User } from '../database/schema.js';
import { store } from '../database/index.js';
import { getClientIp } from './middleware.js';
import { AppError } from './errors.js';

/**
 * Shared 2FA verification logic used by both password login and OAuth 2FA.
 * Verifies TOTP code or recovery code, handles outdated secrets, and manages
 * recovery code consumption + audit logging.
 *
 * @returns void on success, throws AppError on failure
 */
export async function verifyTotpOrRecoveryCode(
  user: User & { totp_secret?: string | null; recovery_codes?: string | null },
  totpCode: string,
  request: FastifyRequest,
  method: string, // e.g. 'password', 'oauth_google'
): Promise<void> {
  const otp = new OTP({ strategy: 'totp' });

  // Check if secret is missing or too short (migration from otplib v12 to v13)
  if (!user.totp_secret || user.totp_secret.length < 16) {
    const reason = !user.totp_secret ? '2FA secret decryption failed' : '2FA secret too short';
    request.log.warn({ userId: user.id, reason }, 'Disabling 2FA');
    await store.users.update(user.id, {
      totp_enabled: false,
      totp_secret_encrypted: null,
      recovery_codes_encrypted: null,
    });
    throw new AppError(
      400,
      'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
      'TOTP_SECRET_OUTDATED',
    );
  }

  let isValidTotp = false;
  try {
    const result = await otp.verify({
      token: totpCode,
      secret: user.totp_secret,
      epochTolerance: 1, // ±30s tolerance for clock drift
    });
    isValidTotp = result.valid;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === 'SecretTooShortError') {
      request.log.warn({ userId: user.id }, '2FA secret validation failed, disabling 2FA');
      await store.users.update(user.id, {
        totp_enabled: false,
        totp_secret_encrypted: null,
        recovery_codes_encrypted: null,
      });
      throw new AppError(
        400,
        'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
        'TOTP_SECRET_OUTDATED',
      );
    }
    request.log.warn({ error, userId: user.id }, 'TOTP verification error, treating as invalid code');
    isValidTotp = false;
  }

  // If invalid, try recovery codes
  if (!isValidTotp) {
    let recoveryCodes: string[] = [];
    if (user.recovery_codes) {
      try {
        recoveryCodes = JSON.parse(user.recovery_codes) as string[];
      } catch {
        request.log.error({ userId: user.id }, 'Corrupted recovery codes JSON — treating as empty');
      }
    }

    // Use constant-time comparison to prevent timing attacks
    let codeIndex = -1;
    for (let i = 0; i < recoveryCodes.length; i++) {
      const code = recoveryCodes[i];
      if (code && code.length === totpCode.length) {
        try {
          const a = Buffer.from(code, 'utf8');
          const b = Buffer.from(totpCode, 'utf8');
          if (crypto.timingSafeEqual(a, b)) {
            codeIndex = i;
            break;
          }
        } catch {
          // Continue if lengths don't match exactly
        }
      }
    }

    if (codeIndex === -1) {
      // Audit log for failed 2FA
      const reason = totpCode.length === 8 ? 'invalid_2fa_backup_code' : 'invalid_2fa_code';
      await store.audit.createLog(
        user.id,
        'login_failed',
        JSON.stringify({ reason, method }),
        getClientIp(request),
        request.headers['user-agent'],
      );
      throw new AppError(
        401,
        totpCode.length === 8 ? 'Backup code is incorrect' : '2FA code is incorrect',
        'INVALID_2FA_CODE',
      );
    }

    // Remove used recovery code
    recoveryCodes.splice(codeIndex, 1);
    await store.users.update(user.id, {
      recovery_codes: JSON.stringify(recoveryCodes),
    });

    await store.audit.createLog(
      user.id,
      '2fa_recovery_code_used',
      JSON.stringify({ remaining_codes: recoveryCodes.length, method }),
      getClientIp(request),
      request.headers['user-agent'],
    );
  }
}
