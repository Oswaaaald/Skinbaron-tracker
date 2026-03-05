import { FastifyInstance } from 'fastify';
import { store } from '../database/index.js';
import { AuthService, PasswordChangeSchema, SetPasswordSchema } from '../lib/auth.js';
import { getClientIp, getAuthUser, ACCESS_COOKIE } from '../lib/middleware.js';
import { processAndSaveAvatar, deleteAvatarFile } from '../lib/avatar.js';
import { verifyTotpOrRecoveryCode } from '../lib/two-factor.js';
import { z } from 'zod';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { appConfig } from '../lib/config.js';
import { registerUserAccountRoutes } from './user/account-routes.js';
import { registerUserSecurityRoutes } from './user/security-routes.js';

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

const AvatarSettingsSchema = z.object({
  use_gravatar: z.boolean(),
});

/**
 * User profile routes - Authenticated users can manage their own profile
 */
export default async function userRoutes(fastify: FastifyInstance) {
  // Local hook for defense in depth - ensures all routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);

  // Rate limiting for sensitive operations
  const sensitiveOperationRateLimit = {
    max: 5,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many attempts. Please try again in 1 minute.',
    }),
  };

  // Strict rate limit for avatar operations (file I/O + image processing)
  const avatarRateLimit = {
    max: 3,
    timeWindow: '5 minutes',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many avatar changes. Please try again in 5 minutes.',
    }),
  };

  // Stricter rate limit for expensive/destructive operations
  const heavyOperationRateLimit = {
    max: 3,
    timeWindow: '5 minutes',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many requests. Please try again later.',
    }),
  };

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

  // ==================== Avatar Management ====================

  /**
   * POST /api/user/avatar - Upload a custom avatar image
   * Security: magic-byte validation, sharp re-encoding (strips EXIF/metadata),
   * random filename, size limit, rate limited
   */
  fastify.post('/avatar', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Upload a custom avatar image (max 5 MB, PNG/JPEG/WebP/GIF)',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      consumes: ['multipart/form-data'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                avatar_url: { type: 'string' },
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
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      const file = await request.file();
      if (!file) {
        throw new AppError(400, 'No file uploaded', 'NO_FILE');
      }

      // Process image (validates magic bytes, resizes, strips metadata, converts to WebP)
      let filename: string;
      try {
        filename = await processAndSaveAvatar(file);
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to process image';
        throw new AppError(400, msg, 'INVALID_IMAGE');
      }

      // Delete old avatar file if it exists
      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      // Update database
      await store.users.update(userId, { avatar_filename: filename });

      // Audit log
      await store.audit.createLog(userId, 'avatar_uploaded', JSON.stringify({ filename }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, avatar_filename: filename }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar upload');
    }
  });

  /**
   * DELETE /api/user/avatar - Remove custom avatar (revert to gravatar or initials)
   */
  fastify.delete('/avatar', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Remove custom avatar',
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
                avatar_url: { type: 'string', nullable: true },
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
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      if (user.avatar_filename) {
        await deleteAvatarFile(user.avatar_filename);
      }

      await store.users.update(userId, { avatar_filename: null });

      await store.audit.createLog(userId, 'avatar_removed', JSON.stringify({ had_custom: !!user.avatar_filename }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, avatar_filename: null }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar delete');
    }
  });

  /**
   * PATCH /api/user/avatar-settings - Toggle Gravatar fallback
   */
  fastify.patch('/avatar-settings', {
    config: { rateLimit: avatarRateLimit },
    schema: {
      description: 'Toggle Gravatar fallback for avatar',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['use_gravatar'],
        properties: {
          use_gravatar: { type: 'boolean' },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                use_gravatar: { type: 'boolean' },
                avatar_url: { type: 'string', nullable: true },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const { use_gravatar } = validateWithZod(AvatarSettingsSchema, request.body);

      const user = await store.users.findById(userId);
      if (!user) throw new AppError(404, 'User not found', 'USER_NOT_FOUND');

      await store.users.update(userId, { use_gravatar });

      await store.audit.createLog(userId, 'gravatar_toggled', JSON.stringify({ use_gravatar }), getClientIp(request), request.headers['user-agent']);

      const avatarUrl = AuthService.getAvatarUrl({ ...user, use_gravatar }, appConfig.NEXT_PUBLIC_API_URL);

      return reply.status(200).send({
        success: true,
        data: { use_gravatar, avatar_url: avatarUrl },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Avatar settings');
    }
  });
  registerUserAccountRoutes(fastify, {
    sensitiveOperationRateLimit,
    heavyOperationRateLimit,
  });
  registerUserSecurityRoutes(fastify, { sensitiveOperationRateLimit });
}
