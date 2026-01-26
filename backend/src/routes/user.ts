import { FastifyInstance } from 'fastify';
import { getStore } from '../lib/store.js';
import { AuthService, PasswordChangeSchema } from '../lib/auth.js';
import { getClientIp } from '../lib/middleware.js';
import { OTP } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { z } from 'zod';

const UpdateProfileSchema = z.object({
  username: z.string().min(3).max(50).optional(),
  email: z.string().email().optional(),
}).refine(data => data.username || data.email, {
  message: 'At least one field must be provided',
});

/**
 * User profile routes - Authenticated users can manage their own profile
 */
export default async function userRoutes(fastify: FastifyInstance) {
  const store = getStore();

  /**
   * GET /api/user/profile - Get current user profile
   */
  fastify.get('/profile', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get current user profile',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = request.user!.id;
      const user = store.getUserById(userId);
      
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
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
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get user profile');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get user profile',
      });
    }
  });

  /**
   * GET /api/user/stats - Get current user statistics
   */
  fastify.get('/stats', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get current user statistics',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;

      const rulesCount = store.getRulesByUserId(userId).length;
      const alertsCount = store.getUserAlerts(userId).length;
      const webhooksCount = store.getUserWebhooks(userId).length;

      return reply.status(200).send({
        success: true,
        data: {
          rules_count: rulesCount,
          alerts_count: alertsCount,
          webhooks_count: webhooksCount,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get user stats');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get user stats',
      });
    }
  });

  /**
   * PATCH /api/user/profile - Update current user profile
   */
  fastify.patch('/profile', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Update current user profile',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;
      const updates = UpdateProfileSchema.parse(request.body);

      // Get current user to check admin status
      const currentUser = store.getUserById(userId);
      if (!currentUser) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Check if username is already taken by another user
      if (updates.username) {
        const existingUser = store.getUserByUsername(updates.username);
        if (existingUser && existingUser.id !== userId) {
          return reply.status(400).send({
            success: false,
            error: 'Validation failed',
            message: 'Username already taken',
          });
        }
      }

      // Non-admin users cannot change their email
      if (updates.email && !currentUser.is_admin) {
        return reply.status(403).send({
          success: false,
          error: 'Permission denied',
          message: 'Only administrators can change their email address',
        });
      }

      // Check if email is already taken by another user
      if (updates.email) {
        const existingUser = store.getUserByEmail(updates.email);
        if (existingUser && existingUser.id !== userId) {
          return reply.status(400).send({
            success: false,
            error: 'Validation failed',
            message: 'Email already in use',
          });
        }
      }

      // Update user profile
      const changedFields = Object.keys(updates);
      store.updateUser(userId, updates);
      
      // Audit log for profile update
      store.createAuditLog(
        userId,
        updates.email ? 'email_changed' : 'profile_updated',
        JSON.stringify({ fields: changedFields, new_email: updates.email }),
        getClientIp(request),
        request.headers['user-agent']
      );
      
      // Get updated user data
      const updatedUser = store.getUserById(userId);
      if (!updatedUser) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
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
      request.log.error({ error }, 'Failed to update profile');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid input',
          details: error.issues,
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to update profile',
      });
    }
  });

  /**
   * PATCH /api/user/password - Update current user password
   */
  fastify.patch('/password', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Update current user password',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;
      const passwordData = PasswordChangeSchema.parse(request.body);

      // Get user
      const user = store.getUserById(userId);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Verify current password
      const isValidPassword = await AuthService.verifyPassword(passwordData.current_password, user.password_hash);
      if (!isValidPassword) {
        // Audit log for failed password change attempt
        store.createAuditLog(
          userId,
          'password_change_failed',
          JSON.stringify({ reason: 'invalid_current_password' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        return reply.status(401).send({
          success: false,
          error: 'Current password is incorrect',
        });
      }

      // Check if new password is same as current password
      const isSamePassword = await AuthService.verifyPassword(passwordData.new_password, user.password_hash);
      if (isSamePassword) {
        store.createAuditLog(
          userId,
          'password_change_failed',
          JSON.stringify({ reason: 'same_password' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        return reply.status(400).send({
          success: false,
          error: 'Validation failed',
          message: 'New password must be different from current password',
        });
      }

      // Hash new password
      const newPasswordHash = await AuthService.hashPassword(passwordData.new_password);

      // Update password
      store.updateUser(userId, { password_hash: newPasswordHash });

      // Audit log for successful password change
      store.createAuditLog(
        userId,
        'password_changed',
        undefined,
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: 'Password updated successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to update password');

      // Handle Zod validation errors
      if (error && typeof error === 'object' && 'issues' in error) {
        const zodError = error as { issues: Array<{ message: string }> };
        const firstIssue = zodError.issues?.[0];
        if (firstIssue?.message) {
          return reply.status(400).send({
            success: false,
            error: 'Validation failed',
            message: firstIssue.message,
          });
        }
      }

      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid input',
          details: error.issues,
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Failed to update password',
      });
    }
  });

  /**
   * DELETE /api/user/account - Delete current user account
   */
  fastify.delete('/account', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Delete current user account and all associated data',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;

      // Delete user (CASCADE will delete all associated data)
      store.deleteUser(userId);

      return reply.status(200).send({
        success: true,
        message: 'Account deleted successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to delete account');
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete account',
      });
    }
  });

  /**
   * POST /api/user/2fa/setup - Generate 2FA setup (secret + QR code)
   */
  fastify.post('/2fa/setup', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Generate 2FA setup credentials',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;
      const user = store.getUserById(userId);

      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
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

      return reply.status(200).send({
        success: true,
        data: {
          secret,
          qrCode,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to generate 2FA setup');
      return reply.status(500).send({
        success: false,
        error: 'Failed to generate 2FA setup',
      });
    }
  });

  /**
   * POST /api/user/2fa/enable - Verify code and enable 2FA
   */
  fastify.post('/2fa/enable', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Verify code and enable 2FA',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        properties: {
          secret: { type: 'string' },
          code: { type: 'string' },
        },
        required: ['secret', 'code'],
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
      const userId = request.user!.id;
      const { secret, code } = request.body as { secret: string; code: string };

      // Verify the code
      const otp = new OTP({ strategy: 'totp' });
      const result = await otp.verify({
        token: code,
        secret,
        epochTolerance: 1, // ±30s tolerance for clock drift
      });
      const isValid = result.valid;

      if (!isValid) {
        return reply.status(400).send({
          success: false,
          error: 'Invalid verification code',
        });
      }

      // Generate 10 recovery codes
      const recoveryCodes = Array.from({ length: 10 }, () => 
        crypto.randomBytes(4).toString('hex').toUpperCase()
      );

      // Save to database
      store.updateUser(userId, {
        totp_secret: secret,
        totp_enabled: 1,
        recovery_codes: JSON.stringify(recoveryCodes),
      });

      // Audit log
      store.createAuditLog(
        userId,
        '2fa_enabled',
        undefined,
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
      request.log.error({ error }, 'Failed to enable 2FA');
      return reply.status(500).send({
        success: false,
        error: 'Failed to enable 2FA',
      });
    }
  });

  /**
   * POST /api/user/2fa/disable - Disable 2FA
   */
  fastify.post('/2fa/disable', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Disable 2FA',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        properties: {
          password: { type: 'string' },
        },
        required: ['password'],
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
      const userId = request.user!.id;
      const { password } = request.body as { password: string };

      const user = store.getUserById(userId);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Verify password
      const isValidPassword = await AuthService.verifyPassword(password, user.password_hash);
      if (!isValidPassword) {
        return reply.status(401).send({
          success: false,
          error: 'Invalid password',
        });
      }

      // Disable 2FA
      store.updateUser(userId, {
        totp_secret: null,
        totp_enabled: 0,
        recovery_codes: null,
      });

      // Audit log
      store.createAuditLog(
        userId,
        '2fa_disabled',
        undefined,
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: '2FA disabled successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to disable 2FA');
      return reply.status(500).send({
        success: false,
        error: 'Failed to disable 2FA',
      });
    }
  });

  /**
   * GET /api/user/2fa/status - Check 2FA status
   */
  fastify.get('/2fa/status', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get 2FA status for current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;
      const user = store.getUserById(userId);

      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      return reply.status(200).send({
        success: true,
        data: {
          enabled: Boolean(user.totp_enabled),
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get 2FA status');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get 2FA status',
      });
    }
  });

  /**
   * GET /api/user/audit-logs - Get current user's audit logs
   */
  fastify.get('/audit-logs', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get security audit logs for current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }],
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
      const userId = request.user!.id;
      const { limit = 100 } = request.query as { limit?: number };

      const logs = store.getAuditLogsByUserId(userId, limit);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get audit logs');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get audit logs',
      });
    }
  });
}
