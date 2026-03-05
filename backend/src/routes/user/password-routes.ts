import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { AuthService, PasswordChangeSchema, SetPasswordSchema } from '../../lib/auth.js';
import { getClientIp, getAuthUser, ACCESS_COOKIE } from '../../lib/middleware.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';

type RegisterUserPasswordRoutesOptions = {
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

export function registerUserPasswordRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserPasswordRoutesOptions,
): void {
  /**
   * PATCH /api/user/password - Update current user password
   */
  fastify.patch('/password', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Update current user password',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          current_password: { type: 'string', minLength: 1, maxLength: 128 },
          new_password: { type: 'string', minLength: 8, maxLength: 128 },
        },
        required: ['current_password', 'new_password'],
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
      const passwordData = validateWithZod(PasswordChangeSchema, request.body);

      // Get user
      const user = await store.users.findById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Verify current password (OAuth-only users have no password)
      if (!user.password_hash) {
        throw new AppError(400, 'Your account uses social login and has no password set.', 'NO_PASSWORD');
      }
      const isValidPassword = await AuthService.verifyPassword(passwordData.current_password, user.password_hash);
      if (!isValidPassword) {
        // Audit log for failed password change attempt
        await store.audit.createLog(
          userId,
          'password_change_failed',
          JSON.stringify({ reason: 'invalid_current_password' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        throw new AppError(401, 'Current password is incorrect', 'INVALID_PASSWORD');
      }

      // Check if new password is same as current password
      const isSamePassword = await AuthService.verifyPassword(passwordData.new_password, user.password_hash);
      if (isSamePassword) {
        await store.audit.createLog(
          userId,
          'password_change_failed',
          JSON.stringify({ reason: 'same_password' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        throw new AppError(400, 'New password must be different from current password', 'SAME_PASSWORD');
      }

      // Hash new password
      const newPasswordHash = await AuthService.hashPassword(passwordData.new_password);

      // Update password
      await store.users.update(userId, { password_hash: newPasswordHash });

      // Invalidate all existing sessions (revoke all refresh tokens + blacklist their access tokens)
      // This forces re-login on all devices after a password change
      const revokedJtis = await store.auth.revokeAllForUser(userId);
      const accessExpiry = Date.now() + 15 * 60 * 1000;
      await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, userId, accessExpiry, 'password_change')));

      // Also blacklist the current request's access token (belt-and-suspenders)
      const accessToken = AuthService.extractTokenFromHeader(request.headers.authorization ?? '') || request.cookies?.[ACCESS_COOKIE];
      if (accessToken) {
        const tokenPayload = AuthService.verifyToken(accessToken, 'access');
        if (tokenPayload?.jti) {
          const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
          await store.auth.blacklistAccessToken(tokenPayload.jti, userId, exp, 'password_change');
        }
      }

      // Audit log for successful password change
      await store.audit.createLog(
        userId,
        'password_changed',
        JSON.stringify({ success: true }),
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: 'Password updated successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Update password');
    }
  });

  /**
   * POST /api/user/set-password - Set password for OAuth-only users who have no password
   */
  fastify.post('/set-password', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Set password for OAuth-only users',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          new_password: { type: 'string', minLength: 8, maxLength: 128 },
          totp_code: { type: 'string', maxLength: 8, description: 'Required if 2FA is enabled (re-authentication)' },
        },
        required: ['new_password'],
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
      const passwordData = validateWithZod(SetPasswordSchema, request.body);

      const user = await store.users.findById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Only allow if user has no password (OAuth-only account)
      if (user.password_hash) {
        throw new AppError(400, 'You already have a password set. Use the change password form instead.', 'PASSWORD_ALREADY_SET');
      }

      // Re-auth: require TOTP verification for OAuth-only users with 2FA enabled
      if (user.totp_enabled) {
        if (!passwordData.totp_code) {
          throw new AppError(400, '2FA code is required to set a password', 'TOTP_REQUIRED');
        }
        const userWith2FA = await store.users.findById(userId, true);
        if (userWith2FA) {
          await verifyTotpOrRecoveryCode(userWith2FA, passwordData.totp_code, request, 'set_password');
        }
      }

      // Hash and set the new password
      const newPasswordHash = await AuthService.hashPassword(passwordData.new_password);
      await store.users.update(userId, { password_hash: newPasswordHash });

      // Audit log
      await store.audit.createLog(
        userId,
        'password_changed',
        JSON.stringify({ method: 'set_initial_password' }),
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: 'Password set successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Set password');
    }
  });
}
