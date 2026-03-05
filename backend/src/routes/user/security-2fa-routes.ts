import type { FastifyInstance } from 'fastify';
import { OTP } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import { encryptData } from '../../database/utils/encryption.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { RECOVERY_CODE_COUNT, RECOVERY_CODE_BYTES } from '../../lib/config.js';
import { Enable2FASchema, Disable2FASchema } from '../../database/validation-schemas.js';
import { PENDING_2FA_TTL, type RegisterUserSecurityRoutesOptions } from './security-types.js';

export function registerUserTwoFactorRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserSecurityRoutesOptions,
): void {
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

      if (user.totp_enabled) {
        throw new AppError(400, 'Two-factor authentication is already enabled. Disable it first to re-setup.', '2FA_ALREADY_ENABLED');
      }

      const otp = new OTP({ strategy: 'totp' });
      const secret = otp.generateSecret(20);
      const otpauth = otp.generateURI({
        issuer: 'SkinBaron Tracker',
        label: user.email,
        secret,
      });
      const qrCode = await QRCode.toDataURL(otpauth);

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

      const secret = await store.challenges.get(`2fa_secret:${userId}`);
      if (!secret) {
        throw new AppError(400, 'No pending 2FA setup found. Please start setup again.', 'NO_PENDING_2FA');
      }

      const otp = new OTP({ strategy: 'totp' });
      const result = await otp.verify({
        token: code,
        secret,
        epochTolerance: 1,
      });
      if (!result.valid) {
        throw new AppError(400, 'Invalid verification code', 'INVALID_CODE');
      }

      await store.challenges.consume(`2fa_secret:${userId}`);

      const recoveryCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
        crypto.randomBytes(RECOVERY_CODE_BYTES).toString('hex').toUpperCase(),
      );

      await store.users.update(userId, {
        totp_secret_encrypted: encryptData(secret),
        totp_enabled: true,
        recovery_codes_encrypted: encryptData(JSON.stringify(recoveryCodes)),
      });

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

      if (user.password_hash) {
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      } else {
        if (!totp_code) {
          throw new AppError(400, '2FA code is required to disable two-factor authentication', 'TOTP_REQUIRED');
        }
        await verifyTotpOrRecoveryCode(user, totp_code, request, '2fa_disable');
      }

      await store.users.update(userId, {
        totp_secret_encrypted: null,
        totp_enabled: false,
        recovery_codes_encrypted: null,
      });

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
}
