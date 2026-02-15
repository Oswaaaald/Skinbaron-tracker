import { FastifyInstance } from 'fastify';
import { store } from '../database/index.js';
import { AuthService, PasswordChangeSchema, SetPasswordSchema } from '../lib/auth.js';
import { getClientIp, getAuthUser, ACCESS_COOKIE, clearAuthCookies } from '../lib/middleware.js';
import { encryptData } from '../database/utils/encryption.js';
import { OTP } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { z } from 'zod';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';

/**
 * Server-side store for pending 2FA secrets.
 * Keyed by userId → { secret, expiresAt }.
 * Prevents the client from supplying a secret they control.
 */
const pending2FASecrets = new Map<number, { secret: string; expiresAt: number }>();
const PENDING_2FA_TTL = 10 * 60 * 1000; // 10 minutes

// Periodic cleanup of expired entries to prevent memory leaks
const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [userId, entry] of pending2FASecrets) {
    if (now > entry.expiresAt) pending2FASecrets.delete(userId);
  }
}, CLEANUP_INTERVAL).unref(); // unref so it doesn't keep the process alive

function storePending2FA(userId: number, secret: string): void {
  pending2FASecrets.set(userId, { secret, expiresAt: Date.now() + PENDING_2FA_TTL });
}

function consumePending2FA(userId: number): string | null {
  const entry = pending2FASecrets.get(userId);
  if (!entry) return null;
  pending2FASecrets.delete(userId);
  if (Date.now() > entry.expiresAt) return null;
  return entry.secret;
}

/** Peek at the pending secret without consuming it (for verification attempts) */
function getPending2FA(userId: number): string | null {
  const entry = pending2FASecrets.get(userId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    pending2FASecrets.delete(userId);
    return null;
  }
  return entry.secret;
}

const UpdateProfileSchema = z.object({
  username: z.string().min(3).max(20).optional(),
  email: z.string().email().optional(),
}).refine(data => data.username || data.email, {
  message: 'At least one field must be provided',
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
      const user = await store.getUserById(userId);
      
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      return reply.status(200).send({
        success: true,
        data: {
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
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
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 50 },
          email: { type: 'string', format: 'email' },
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
      const currentUser = await store.getUserById(userId);
      if (!currentUser) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Check if username is already taken by another user
      if (updates.username) {
        const existingUser = await store.getUserByUsername(updates.username);
        if (existingUser && existingUser.id !== userId) {
          throw new AppError(400, 'Username already taken', 'USERNAME_TAKEN');
        }
      }

      // Non-admin users can only change their email to one of their linked OAuth provider emails
      if (updates.email && !currentUser.is_admin) {
        const oauthAccounts = await store.getOAuthAccountsByUserId(userId);
        const oauthEmails = oauthAccounts.map(a => a.provider_email).filter(Boolean);
        if (!oauthEmails.includes(updates.email)) {
          throw new AppError(403, 'You can only change your email to one of your linked OAuth provider emails', 'PERMISSION_DENIED');
        }
      }

      // Check if email is already taken by another user (primary email)
      if (updates.email) {
        // For non-admins, the email was already validated as one of their OAuth provider emails (above).
        // OAuth-verified email is the strongest proof of ownership, so the current user can reclaim it
        // unless the other user also has OAuth proof of the same email.
        const isOAuthVerified = !currentUser.is_admin; // non-admins can only pick from OAuth emails

        const existingUser = await store.getUserByEmail(updates.email);
        if (existingUser && existingUser.id !== userId) {
          if (isOAuthVerified) {
            // Check if the conflicting user also has OAuth proof of this email
            const otherOAuthAccounts = await store.getOAuthAccountsByUserId(existingUser.id);
            const otherHasOAuthProof = otherOAuthAccounts.some(a => a.provider_email === updates.email);

            if (otherHasOAuthProof) {
              throw new AppError(400, 'Email already in use by another verified account', 'EMAIL_IN_USE');
            }

            // Current user has OAuth proof, other doesn't → displace their email
            const displacedEmail = `displaced_${existingUser.id}_${Date.now()}@placeholder.local`;
            await store.updateUser(existingUser.id, { email: displacedEmail });
            await store.createAuditLog(
              existingUser.id,
              'email_changed',
              JSON.stringify({ new_email: displacedEmail, reason: 'displaced_by_oauth_owner', displaced_by: userId }),
              getClientIp(request),
              request.headers['user-agent'],
            );
          } else {
            // Admin free-text input — standard uniqueness check
            throw new AppError(400, 'Email already in use', 'EMAIL_IN_USE');
          }
        }

        // Also check if email is used as an OAuth provider email by another user
        const oauthWithEmail = await store.findOAuthAccountByEmail(updates.email, userId);
        if (oauthWithEmail) {
          throw new AppError(400, 'Email already in use', 'EMAIL_IN_USE');
        }
      }

      // Update user profile
      await store.updateUser(userId, updates);
      
      // Audit log for profile update - create separate logs for email and username changes
      if (updates.email) {
        await store.createAuditLog(
          userId,
          'email_changed',
          JSON.stringify({ new_email: updates.email }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }
      
      if (updates.username) {
        await store.createAuditLog(
          userId,
          'username_changed',
          JSON.stringify({ new_username: updates.username }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }
      
      // Get updated user data
      const updatedUser = await store.getUserById(userId);
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
          avatar_url: AuthService.getGravatarUrl(updatedUser.email),
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
        properties: {
          current_password: { type: 'string', minLength: 1 },
          new_password: { type: 'string', minLength: 8 },
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
      const user = await store.getUserById(userId);
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
        await store.createAuditLog(
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
        await store.createAuditLog(
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
      await store.updateUser(userId, { password_hash: newPasswordHash });

      // Invalidate all existing sessions (revoke all refresh tokens)
      // This forces re-login on all devices after a password change
      await store.revokeAllRefreshTokensForUser(userId);

      // Blacklist the current access token so it cannot be reused
      const accessToken = AuthService.extractTokenFromHeader(request.headers.authorization ?? '') || request.cookies?.[ACCESS_COOKIE];
      if (accessToken) {
        const tokenPayload = AuthService.verifyToken(accessToken, 'access');
        if (tokenPayload?.jti) {
          const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
          await store.blacklistAccessToken(tokenPayload.jti, userId, exp, 'password_change');
        }
      }

      // Audit log for successful password change
      await store.createAuditLog(
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
        properties: {
          new_password: { type: 'string', minLength: 8 },
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

      const user = await store.getUserById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Only allow if user has no password (OAuth-only account)
      if (user.password_hash) {
        throw new AppError(400, 'You already have a password set. Use the change password form instead.', 'PASSWORD_ALREADY_SET');
      }

      // Hash and set the new password
      const newPasswordHash = await AuthService.hashPassword(passwordData.new_password);
      await store.updateUser(userId, { password_hash: newPasswordHash });

      // Audit log
      await store.createAuditLog(
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

  /**
   * GET /api/user/data-export - GDPR data export (Art. 20 data portability)
   */
  fastify.get('/data-export', {
    config: {
      rateLimit: heavyOperationRateLimit,
    },
    schema: {
      description: 'Export all personal data (GDPR Art. 20)',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const user = await store.getUserById(userId);

      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Collect all user data (no limits — full GDPR export)
      const rules = await store.getRulesByUserId(userId);
      const webhooks = await store.getUserWebhooksByUserId(userId, false); // Don't decrypt URLs
      const alerts = await store.getAlertsByUserId(userId, 0, 0); // limit=0 → all alerts
      const auditLogs = await store.getAuditLogsByUserId(userId, 0); // limit=0 → all logs
      const oauthAccounts = await store.getOAuthAccountsByUserId(userId);

      const exportData = {
        profile: {
          id: user.id,
          username: user.username,
          email: user.email,
          is_admin: user.is_admin,
          is_approved: user.is_approved,
          two_factor_enabled: user.totp_enabled,
          tos_accepted_at: user.tos_accepted_at,
          created_at: user.created_at,
          updated_at: user.updated_at,
        },
        oauth_accounts: oauthAccounts.map(a => ({
          provider: a.provider,
          provider_email: a.provider_email,
          created_at: a.created_at,
        })),
        rules: rules.map(r => ({
          id: r.id,
          search_item: r.search_item,
          min_price: r.min_price,
          max_price: r.max_price,
          min_wear: r.min_wear,
          max_wear: r.max_wear,
          stattrak_filter: r.stattrak_filter,
          souvenir_filter: r.souvenir_filter,
          sticker_filter: r.sticker_filter,
          enabled: r.enabled,
          webhook_ids: r.webhook_ids,
          created_at: r.created_at,
          updated_at: r.updated_at,
        })),
        webhooks: webhooks.map(w => ({
          id: w.id,
          name: w.name,
          webhook_type: w.webhook_type,
          notification_style: w.notification_style,
          is_active: w.is_active,
          created_at: w.created_at,
          updated_at: w.updated_at,
          // webhook_url omitted for security (encrypted)
        })),
        alerts: alerts.map(a => ({
          id: a.id,
          rule_id: a.rule_id,
          item_name: a.item_name,
          price: a.price,
          wear_value: a.wear_value,
          stattrak: a.stattrak,
          souvenir: a.souvenir,
          has_stickers: a.has_stickers,
          skin_url: a.skin_url,
          sale_id: a.sale_id,
          notified_at: a.notified_at,
          sent_at: a.sent_at,
        })),
        audit_logs: auditLogs.map(l => ({
          id: l.id,
          event_type: l.event_type,
          event_data: l.event_data,
          ip_address: l.ip_address,
          user_agent: l.user_agent,
          created_at: l.created_at,
        })),
        exported_at: new Date().toISOString(),
      };

      // Log the export action
      await store.createAuditLog(userId, 'data_export', undefined, getClientIp(request));

      return reply.status(200).send({
        success: true,
        data: exportData,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Data export');
    }
  });

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
        properties: {
          password: { type: 'string' },
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
      const { password } = request.body as { password?: string };

      const user = await store.getUserById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Verify password before allowing account deletion (skip for OAuth-only users)
      if (user.password_hash) {
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      }
      // OAuth-only users can delete without password (username confirmation is done on frontend)

      // Delete user (CASCADE will automatically delete all associated data including refresh tokens)
      await store.deleteUser(userId);

      // Clear auth cookies so the browser doesn't retain stale tokens
      clearAuthCookies(reply);

      return reply.status(200).send({
        success: true,
        message: 'Account deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete account');
    }
  });

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
      const user = await store.getUserById(userId);

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
      storePending2FA(userId, secret);

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
        properties: {
          code: { type: 'string' },
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
      const { code } = request.body as { code: string };

      // Retrieve the secret stored server-side during /2fa/setup (peek, don't consume yet)
      const secret = getPending2FA(userId);
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
      consumePending2FA(userId);

      // Generate 10 recovery codes
      const recoveryCodes = Array.from({ length: 10 }, () => 
        crypto.randomBytes(4).toString('hex').toUpperCase()
      );

      // Encrypt and save to database
      await store.updateUser(userId, {
        totp_secret_encrypted: encryptData(secret),
        totp_enabled: true,
        recovery_codes_encrypted: encryptData(JSON.stringify(recoveryCodes)),
      });

      // Audit log
      await store.createAuditLog(
        userId,
        '2fa_enabled',
        JSON.stringify({ method: '2fa_enabled' }),
        getClientIp(request),
        request.headers['user-agent']
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
        properties: {
          password: { type: 'string' },
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
      const { password } = request.body as { password?: string };

      const user = await store.getUserById(userId);
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }

      // Verify password (skip for OAuth-only users)
      if (user.password_hash) {
        if (!password) {
          throw new AppError(400, 'Password is required', 'PASSWORD_REQUIRED');
        }
        const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
          throw new AppError(401, 'Invalid password', 'INVALID_PASSWORD');
        }
      }

      // Disable 2FA
      await store.updateUser(userId, {
        totp_secret_encrypted: null,
        totp_enabled: false,
        recovery_codes_encrypted: null,
      });

      // Audit log
      await store.createAuditLog(
        userId,
        '2fa_disabled',
        JSON.stringify({ method: '2fa_disabled' }),
        getClientIp(request),
        request.headers['user-agent']
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
      const user = await store.getUserById(userId);

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
          limit: { type: 'number', default: 100, maximum: 500 },
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
      const { limit = 100 } = request.query as { limit?: number };

      const logs = await store.getAuditLogsByUserId(userId, limit);

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
      const accounts = await store.getOAuthAccountsByUserId(userId);
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
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    try {
      const user = getAuthUser(request);
      const { provider } = request.params;
      const accounts = await store.getOAuthAccountsByUserId(user.id);

      const target = accounts.find(a => a.provider === provider);
      if (!target) {
        throw new AppError(404, 'This OAuth provider is not linked to your account', 'OAUTH_NOT_LINKED');
      }

      // Prevent unlinking the last login method
      const fullUser = await store.getUserById(user.id);
      const hasPassword = !!fullUser?.password_hash;
      if (!hasPassword && accounts.length <= 1) {
        throw new AppError(
          400,
          'Cannot unlink your only login method. Set a password first.',
          'LAST_LOGIN_METHOD',
        );
      }

      await store.unlinkOAuthAccount(user.id, provider);

      await store.createAuditLog(
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