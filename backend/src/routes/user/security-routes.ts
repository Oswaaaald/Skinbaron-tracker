import { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { encryptData } from '../../database/utils/encryption.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import { OTP } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { appConfig, RECOVERY_CODE_COUNT, RECOVERY_CODE_BYTES } from '../../lib/config.js';
import {
  Enable2FASchema,
  Disable2FASchema,
  PasskeyParamsSchema,
  PasskeyRenameSchema,
  PasskeyRegisterVerifySchema,
  UserAuditQuerySchema,
  OAuthUnlinkParamsSchema,
} from '../../database/schemas.js';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { resolvePasskeyName } from '../../lib/passkey-aaguids.js';

type RegisterUserSecurityRoutesOptions = {
  sensitiveOperationRateLimit: {
    max: number;
    timeWindow: string;
    errorResponseBuilder: () => {
      statusCode: number;
      success: boolean;
      error: string;
      message: string;
    };
  };
};

// TTL constants for pending challenges (stored in PostgreSQL)
const PENDING_2FA_TTL = 10 * 60 * 1000; // 10 minutes
const WEBAUTHN_CHALLENGE_TTL = 5 * 60 * 1000; // 5 minutes

export function registerUserSecurityRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserSecurityRoutesOptions,
): void {
  /**
   * POST /api/user/2fa/setup - Generate 2FA setup (secret + QR code)
   */
  fastify.post('/2fa/setup', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Generate 2FA setup credentials',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                secret: { type: 'string' },
                qrCode: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);

      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Block setup if 2FA is already enabled — require disable first
      if (user.totp_enabled) {
        throw new AppError(400, 'Two-factor authentication is already enabled. Disable it first to re-setup.', '2FA_ALREADY_ENABLED');
      }

      // Generate secret (otplib v13 requires minimum 16 characters)
      const otp = new OTP({ strategy: 'totp' });
      const secret = otp.generateSecret(20);

      // Generate OTP auth URL
      const otpauth = otp.generateURI({
        issuer: 'SkinBaron Tracker',
        label: user.email,
        secret,
      });

      // Generate QR code
      const qrCode = await QRCode.toDataURL(otpauth);

      // Store secret server-side (client only gets it for display, cannot tamper on enable)
      await store.challenges.store(`2fa_secret:${userId}`, '2fa_secret', secret, PENDING_2FA_TTL);

      return reply.status(200).send({
        success: true,
        data: {
          secret,
          qrCode,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Generate 2FA setup');
    }
  });

  /**
   * POST /api/user/2fa/enable - Verify code and enable 2FA
   */
  fastify.post('/2fa/enable', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Verify code and enable 2FA',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          code: { type: 'string', minLength: 6, maxLength: 6 },
        },
        required: ['code'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                recovery_codes: {
                  type: 'array',
                  items: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { code } = validateWithZod(Enable2FASchema, request.body);

      // Retrieve the secret stored server-side during /2fa/setup (peek, don't consume yet)
      const secret = await store.challenges.get(`2fa_secret:${userId}`);
      if (!secret) {
        throw new AppError(400, 'No pending 2FA setup found. Please start setup again.', 'NO_PENDING_2FA');
      }

      // Verify the code
      const otp = new OTP({ strategy: 'totp' });
      const result = await otp.verify({
        token: code,
        secret,
        epochTolerance: 1, // ±30s tolerance for clock drift
      });
      const isValid = result.valid;

      if (!isValid) {
        throw new AppError(400, 'Invalid verification code', 'INVALID_CODE');
      }

      // Code is valid — now consume (delete) the pending secret
      await store.challenges.consume(`2fa_secret:${userId}`);

      // Generate recovery codes
      const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
        crypto.randomBytes(RECOVERY_CODE_BYTES).toString('hex').toUpperCase(),
      );

      // Encrypt and save to database
      await store.users.update(userId, {
        totp_secret_encrypted: encryptData(secret),
        totp_enabled: true,
        recovery_codes_encrypted: encryptData(JSON.stringify(recoveryCodes)),
      });

      // Audit log
      await store.audit.createLog(
        userId,
        '2fa_enabled',
        JSON.stringify({ method: '2fa_enabled' }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: '2FA enabled successfully',
        data: {
          recovery_codes: recoveryCodes,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Enable 2FA');
    }
  });

  /**
   * POST /api/user/2fa/disable - Disable 2FA
   */
  fastify.post('/2fa/disable', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Disable 2FA',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          password: { type: 'string', maxLength: 128 },
          totp_code: { type: 'string', maxLength: 8, description: 'Required for OAuth-only users (no password)' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { password, totp_code } = validateWithZod(Disable2FASchema, request.body);

      const user = await store.users.findById(userId, true);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Verify identity before disabling 2FA
      if (user.password_hash) {
        // Password users: verify password
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      } else {
        // OAuth-only users: require TOTP code or recovery code as proof of identity
        if (!totp_code) {
          throw new AppError(400, '2FA code is required to disable two-factor authentication', 'TOTP_REQUIRED');
        }
        await verifyTotpOrRecoveryCode(user, totp_code, request, '2fa_disable');
      }

      // Disable 2FA
      await store.users.update(userId, {
        totp_secret_encrypted: null,
        totp_enabled: false,
        recovery_codes_encrypted: null,
      });

      // Audit log
      await store.audit.createLog(
        userId,
        '2fa_disabled',
        JSON.stringify({ method: '2fa_disabled' }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Disable 2FA');
    }
  });

  /**
   * GET /api/user/2fa/status - Check 2FA status
   */
  fastify.get('/2fa/status', {
    schema: {
      description: 'Get 2FA status for current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                enabled: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);

      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      return reply.status(200).send({
        success: true,
        data: {
          enabled: user.totp_enabled,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get 2FA status');
    }
  });

  // ==================== Passkeys / WebAuthn ====================

  const rpID = appConfig.WEBAUTHN_RP_ID;
  const rpName = appConfig.WEBAUTHN_RP_NAME;
  const rpOrigin = appConfig.WEBAUTHN_RP_ORIGIN;

  /**
   * GET /api/user/passkeys - List user's passkeys
   */
  fastify.get('/passkeys', {
    schema: {
      description: 'List registered passkeys',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const keys = await store.passkeys.findByUserId(userId);
      return reply.status(200).send({
        success: true,
        data: keys.map((k) => ({
          id: k.id,
          name: k.name,
          device_type: k.device_type,
          backed_up: k.backed_up,
          transports: k.transports ? JSON.parse(k.transports) as string[] : [],
          created_at: k.created_at,
          last_used_at: k.last_used_at,
        })),
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List passkeys');
    }
  });

  /**
   * POST /api/user/passkeys/register-options - Generate registration options
   */
  fastify.post('/passkeys/register-options', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Generate WebAuthn registration options',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      const existingKeys = await store.passkeys.findByUserId(userId);

      // Limit max passkeys per user
      if (existingKeys.length >= 10) {
        throw new AppError(400, 'Maximum of 10 passkeys allowed per account', 'MAX_PASSKEYS_REACHED');
      }

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userName: user.username,
        userDisplayName: user.username,
        attestationType: 'none',
        excludeCredentials: existingKeys.map((k) => ({
          id: k.credential_id,
          transports: k.transports ? (JSON.parse(k.transports) as AuthenticatorTransportFuture[]) : undefined,
        })),
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'preferred',
        },
      });

      // Store challenge server-side
      await store.challenges.store(`webauthn_reg:${userId}`, 'webauthn_registration', options.challenge, WEBAUTHN_CHALLENGE_TTL);

      return reply.status(200).send({ success: true, data: options });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey register options');
    }
  });

  /**
   * POST /api/user/passkeys/register-verify - Verify registration response
   */
  fastify.post('/passkeys/register-verify', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Verify WebAuthn registration response',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          credential: { type: 'object', maxProperties: 20 },
          name: { type: 'string', maxLength: 64 },
        },
        required: ['credential'],
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { credential, name: rawName } = validateWithZod(PasskeyRegisterVerifySchema, request.body);

      // Sanitize passkey name
      const name = rawName ? rawName.trim().replace(/[<>]/g, '').slice(0, 64) : undefined;

      const challengeValue = await store.challenges.consume(`webauthn_reg:${userId}`);
      if (!challengeValue) {
        throw new AppError(400, 'Registration challenge expired. Please try again.', 'CHALLENGE_EXPIRED');
      }

      const verification = await verifyRegistrationResponse({
        response: credential as unknown as Parameters<typeof verifyRegistrationResponse>[0]['response'],
        expectedChallenge: challengeValue,
        expectedOrigin: rpOrigin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new AppError(400, 'Passkey verification failed', 'VERIFICATION_FAILED');
      }

      const { credential: cred, credentialDeviceType, credentialBackedUp, aaguid } = verification.registrationInfo;

      // cred.id is already a Base64URLString in @simplewebauthn/server v13
      const credentialIdB64 = cred.id;
      // cred.publicKey is a Uint8Array, encode to base64url for storage
      const publicKeyB64 = Buffer.from(cred.publicKey).toString('base64url');

      // Resolve a friendly name from the AAGUID (e.g. "iCloud Keychain", "Dashlane", "YubiKey 5")
      const detectedName = resolvePasskeyName(aaguid, credentialDeviceType, cred.transports);

      const passkey = await store.passkeys.create({
        user_id: userId,
        credential_id: credentialIdB64,
        public_key: publicKeyB64,
        counter: cred.counter,
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp,
        transports: cred.transports ? JSON.stringify(cred.transports) : undefined,
        name: name || detectedName,
      });

      await store.audit.createLog(
        userId,
        'passkey_registered',
        JSON.stringify({ passkey_id: passkey.id, name: passkey.name, device_type: credentialDeviceType, aaguid }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        data: {
          id: passkey.id,
          name: passkey.name,
          device_type: passkey.device_type,
          backed_up: passkey.backed_up,
          created_at: passkey.created_at,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey register verify');
    }
  });

  /**
   * PATCH /api/user/passkeys/:id - Rename a passkey
   */
  fastify.patch<{ Params: { id: string } }>('/passkeys/:id', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Rename a passkey',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: { name: { type: 'string', minLength: 1, maxLength: 64 } },
        required: ['name'],
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id: passkeyId } = validateWithZod(PasskeyParamsSchema, request.params);
      const { name } = validateWithZod(PasskeyRenameSchema, request.body);

      const updated = await store.passkeys.rename(passkeyId, userId, name);
      if (!updated) throw new AppError(404, 'Passkey not found', 'NOT_FOUND');

      return reply.status(200).send({ success: true, message: 'Passkey renamed', data: { id: updated.id, name: updated.name } });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Rename passkey');
    }
  });

  /**
   * DELETE /api/user/passkeys/:id - Delete a passkey
   */
  fastify.delete<{ Params: { id: string } }>('/passkeys/:id', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Delete a passkey',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { id: passkeyId } = validateWithZod(PasskeyParamsSchema, request.params);

      const deleted = await store.passkeys.delete(passkeyId, userId);
      if (!deleted) throw new AppError(404, 'Passkey not found', 'NOT_FOUND');

      await store.audit.createLog(
        userId,
        'passkey_deleted',
        JSON.stringify({ passkey_id: passkeyId }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({ success: true, message: 'Passkey deleted' });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete passkey');
    }
  });

  /**
   * GET /api/user/audit-logs - Get current user's audit logs
   */
  fastify.get('/audit-logs', {
    schema: {
      description: 'Get security audit logs for current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 500 },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  event_type: { type: 'string' },
                  event_data: { type: 'string', nullable: true },
                  ip_address: { type: 'string', nullable: true },
                  user_agent: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { limit } = validateWithZod(UserAuditQuerySchema, request.query);

      const allLogs = await store.audit.getLogsByUserId(userId, limit);

      // Filter out admin-only sanction/moderation events from user-facing logs
      const ADMIN_ONLY_EVENTS = new Set([
        'account_restricted',
        'account_unrestricted',
        'sanction_deleted',
        '2fa_reset_by_admin',
        'passkeys_reset_by_admin',
        'sessions_reset_by_admin',
      ]);
      const logs = allLogs.filter((log) => !ADMIN_ONLY_EVENTS.has(log.event_type));

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get audit logs');
    }
  });

  // ==================== OAuth linked accounts ====================

  /**
   * Get OAuth accounts linked to the current user
   */
  fastify.get('/oauth-accounts', {
    schema: {
      description: 'Get linked OAuth accounts',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  provider: { type: 'string' },
                  provider_email: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const accounts = await store.oauth.findByUserId(userId);
      return reply.status(200).send({ success: true, data: accounts });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get OAuth accounts');
    }
  });

  /**
   * Unlink an OAuth provider from the current user.
   * Blocked if the user has no password and this is their last provider.
   */
  fastify.delete<{ Params: { provider: string } }>('/oauth-accounts/:provider', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Unlink an OAuth provider',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = getAuthUser(request);
      const { provider } = validateWithZod(OAuthUnlinkParamsSchema, request.params);
      const accounts = await store.oauth.findByUserId(user.id);

      const target = accounts.find((a) => a.provider === provider);
      if (!target) {
        throw new AppError(404, 'This OAuth provider is not linked to your account', 'OAUTH_NOT_LINKED');
      }

      // Prevent unlinking the last login method
      const fullUser = await store.users.findById(user.id);
      const hasPassword = !!fullUser?.password_hash;
      if (!hasPassword && accounts.length <= 1) {
        throw new AppError(
          400,
          'Cannot unlink your only login method. Set a password first.',
          'LAST_LOGIN_METHOD',
        );
      }

      await store.oauth.unlink(user.id, provider);

      await store.audit.createLog(
        user.id,
        'oauth_unlinked',
        JSON.stringify({ provider }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({ success: true, message: `${provider} account unlinked` });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Unlink OAuth account');
    }
  });
}
