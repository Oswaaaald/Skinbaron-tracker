import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import {
  getAuthUser,
  ACCESS_COOKIE,
  clearAuthCookies,
} from '../../lib/middleware.js';
import { deleteAvatarFile } from '../../lib/avatar.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { DeleteAccountSchema } from '../../database/schemas.js';

type RegisterUserAccountDeleteRoutesOptions = {
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

export function registerUserAccountDeleteRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserAccountDeleteRoutesOptions,
): void {
  /**
   * DELETE /api/user/account - Delete current user account
   */
  fastify.delete('/account', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Delete current user account and all associated data',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          password: { type: 'string', maxLength: 128 },
          totp_code: { type: 'string', maxLength: 8, description: 'Required for OAuth-only users with 2FA enabled' },
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
      const { password, totp_code } = validateWithZod(DeleteAccountSchema, request.body);

      const user = await store.users.findById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Prevent deleting the last admin account.
      if (user.is_admin) {
        const adminCount = await store.users.countAdmins();
        if (adminCount <= 1) {
          throw new AppError(403, 'Cannot delete your account: you are the last administrator. Transfer admin privileges first.', 'LAST_ADMIN');
        }
      }

      // Verify identity before allowing account deletion.
      if (user.password_hash) {
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      } else if (user.totp_enabled) {
        if (!totp_code) {
          throw new AppError(400, '2FA code is required to delete your account', 'TOTP_REQUIRED');
        }
        const userWith2FA = await store.users.findById(userId, true);
        if (userWith2FA) {
          await verifyTotpOrRecoveryCode(userWith2FA, totp_code, request, 'account_delete');
        }
      }

      await store.audit.logAdminAction(
        userId,
        'account_self_deleted',
        userId,
        JSON.stringify({ username: user.username, email: user.email, was_admin: user.is_admin }),
      );

      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      // Blacklist current access token before deleting user (FK constraint on blacklist table).
      const accessToken =
        AuthService.extractTokenFromHeader(request.headers.authorization ?? '') ||
        request.cookies?.[ACCESS_COOKIE];
      if (accessToken) {
        const tokenPayload = AuthService.verifyToken(accessToken, 'access');
        if (tokenPayload?.jti) {
          const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
          await store.auth.blacklistAccessToken(tokenPayload.jti, userId, exp, 'account_deleted');
        }
      }

      await store.users.delete(userId);
      clearAuthCookies(reply);

      return reply.status(200).send({
        success: true,
        message: 'Account deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete account');
    }
  });
}
