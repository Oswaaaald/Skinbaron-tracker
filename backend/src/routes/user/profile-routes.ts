import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { appConfig } from '../../lib/config.js';

const UpdateProfileSchema = z.object({
  username: z.string()
    .min(3)
    .max(20)
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores')
    .optional(),
  email: z.string().email().optional(),
}).refine(data => data.username || data.email, {
  message: 'At least one field must be provided',
});

type RegisterUserProfileRoutesOptions = {
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

export function registerUserProfileRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserProfileRoutesOptions,
): void {
  /**
   * GET /api/user/profile - Get current user profile
   */
  fastify.get('/profile', {
    schema: {
      description: 'Get current user profile',
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
                id: { type: 'number' },
                username: { type: 'string' },
                email: { type: 'string' },
                avatar_url: { type: 'string' },
                is_admin: { type: 'boolean' },
                is_super_admin: { type: 'boolean' },
                has_password: { type: 'boolean' },
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
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
          use_gravatar: user.use_gravatar,
          is_admin: user.is_admin,
          is_super_admin: user.is_super_admin,
          has_password: !!user.password_hash,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get user profile');
    }
  });

  /**
   * GET /api/user/stats - Get current user statistics
   */
  fastify.get('/stats', {
    schema: {
      description: 'Get current user statistics',
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
                rules_count: { type: 'number' },
                alerts_count: { type: 'number' },
                webhooks_count: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;

      // Use COUNT(*) queries instead of loading all data into memory
      const rulesCount = await store.rules.count(userId);
      const webhooksCount = await store.webhooks.count(userId);

      // Alerts count via JOIN to get user's alerts through their rules
      const alertsCount = await store.alerts.countByUserId(userId);

      return reply.status(200).send({
        success: true,
        data: {
          rules_count: rulesCount,
          alerts_count: alertsCount,
          webhooks_count: webhooksCount,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get user stats');
    }
  });

  /**
   * PATCH /api/user/profile - Update current user profile
   */
  fastify.patch('/profile', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Update current user profile',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 20 },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', maxLength: 128, description: 'Required for email change re-authentication (if user has a password)' },
          totp_code: { type: 'string', maxLength: 8, description: 'Required for email change re-authentication (if 2FA is enabled)' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                username: { type: 'string' },
                email: { type: 'string' },
                avatar_url: { type: 'string' },
                is_admin: { type: 'boolean' },
                is_super_admin: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const updates = validateWithZod(UpdateProfileSchema, request.body);

      // Get current user to check admin status
      const currentUser = await store.users.findById(userId);
      if (!currentUser) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Check if username is already taken by another user
      if (updates.username) {
        const existingUser = await store.users.findByUsername(updates.username);
        if (existingUser && existingUser.id !== userId) {
          throw new AppError(400, 'Username already taken', 'USERNAME_TAKEN');
        }
      }

      // Non-admin users can only change their email to one of their linked OAuth provider emails
      if (updates.email && !currentUser.is_admin) {
        const oauthAccounts = await store.oauth.findByUserId(userId);
        const oauthEmails = oauthAccounts.map(a => a.provider_email).filter(Boolean);
        if (!oauthEmails.includes(updates.email)) {
          throw new AppError(403, 'You can only change your email to one of your linked OAuth provider emails', 'PERMISSION_DENIED');
        }
      }

      // Check if email is already taken by another user
      if (updates.email) {
        const existingUser = await store.users.findByEmail(updates.email);
        if (existingUser && existingUser.id !== userId) {
          throw new AppError(400, 'Email already in use', 'EMAIL_IN_USE');
        }

        // Also check if email is used as an OAuth provider email by another user
        const oauthWithEmail = await store.oauth.findByProviderEmail(updates.email, userId);
        if (oauthWithEmail) {
          throw new AppError(400, 'Email already in use', 'EMAIL_IN_USE');
        }
      }

      // Additional security check for email changes
      // Users with password must provide password. OAuth-only users with 2FA must provide totp_code.
      if (updates.email) {
        const body = request.body as { password?: string; totp_code?: string };
        if (currentUser.password_hash) {
          if (!body.password) {
            throw new AppError(400, 'Password is required to change your email', 'PASSWORD_REQUIRED');
          }
          const isValid = await AuthService.verifyPassword(body.password, currentUser.password_hash);
          if (!isValid) {
            throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
          }
        } else if (currentUser.totp_enabled) {
          if (!body.totp_code) {
            throw new AppError(400, '2FA code is required to change your email', 'TOTP_REQUIRED');
          }
          const userWith2FA = await store.users.findById(userId, true);
          if (!userWith2FA) {
            throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
          }
          await verifyTotpOrRecoveryCode(userWith2FA, body.totp_code, request, 'email_change');
        }
      }

      // Update user profile
      await store.users.update(userId, updates);

      // Audit log for profile update - create separate logs for email and username changes
      if (updates.email) {
        await store.audit.createLog(
          userId,
          'email_changed',
          JSON.stringify({ new_email: updates.email }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }

      if (updates.username) {
        await store.audit.createLog(
          userId,
          'username_changed',
          JSON.stringify({ new_username: updates.username }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }

      // Get updated user data
      const updatedUser = await store.users.findById(userId);
      if (!updatedUser) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      return reply.status(200).send({
        success: true,
        message: 'Profile updated successfully',
        data: {
          id: updatedUser.id,
          username: updatedUser.username,
          email: updatedUser.email,
          avatar_url: AuthService.getAvatarUrl(updatedUser, appConfig.NEXT_PUBLIC_API_URL),
          use_gravatar: updatedUser.use_gravatar,
          is_admin: updatedUser.is_admin,
          is_super_admin: updatedUser.is_super_admin,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Update user profile');
    }
  });
}
