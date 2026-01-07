import { FastifyInstance } from 'fastify';
import { getStore } from '../lib/store.js';
import { AuthService } from '../lib/auth.js';
import { z } from 'zod';

const UpdateProfileSchema = z.object({
  username: z.string().min(3).max(50).optional(),
  email: z.string().email().optional(),
}).refine(data => data.username || data.email, {
  message: 'At least one field must be provided',
});

const UpdatePasswordSchema = z.object({
  current_password: z.string().min(1),
  new_password: z.string().min(8),
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

      // Check if email is already taken by another user
      if (updates.email) {
        const existingUser = store.getUserByEmail(updates.email);
        if (existingUser && existingUser.id !== userId) {
          return reply.status(400).send({
            success: false,
            error: 'Email already in use',
          });
        }
      }

      // Update user profile
      store.updateUser(userId, updates);
      
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
      const { current_password, new_password } = UpdatePasswordSchema.parse(request.body);

      // Get user
      const user = store.getUserById(userId);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Verify current password
      const isValidPassword = await AuthService.verifyPassword(current_password, user.password_hash);
      if (!isValidPassword) {
        return reply.status(401).send({
          success: false,
          error: 'Current password is incorrect',
        });
      }

      // Hash new password
      const newPasswordHash = await AuthService.hashPassword(new_password);

      // Update password
      store.updateUser(userId, { password_hash: newPasswordHash });

      return reply.status(200).send({
        success: true,
        message: 'Password updated successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to update password');

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
}
