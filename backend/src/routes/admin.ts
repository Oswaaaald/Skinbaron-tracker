import { FastifyInstance } from 'fastify';
import { getStore } from '../lib/store.js';

/**
 * Admin routes - All routes require admin privileges
 */
export default async function adminRoutes(fastify: FastifyInstance) {
  const store = getStore();

  /**
   * GET /api/admin/users - List all users (admin only)
   */
  fastify.get('/users', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'List all users (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
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
                  username: { type: 'string' },
                  email: { type: 'string' },
                  is_admin: { type: 'boolean' },
                  is_super_admin: { type: 'boolean' },
                  created_at: { type: 'string' },
                  stats: {
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
        },
      },
    },
  }, async (request, reply) => {
    try {
      const users = store.getAllUsers();

      // Get stats for each user
      const usersWithStats = users.map(user => {
        try {
          const rulesCount = store.getUserRules(user.id).length;
          const alertsCount = store.getUserAlerts(user.id).length;
          const webhooksCount = store.getUserWebhooks(user.id).length;

          return {
            id: user.id,
            username: user.username,
            email: user.email,
            is_admin: user.is_admin || false,
            is_super_admin: user.is_super_admin || false,
            created_at: user.created_at,
            stats: {
              rules_count: rulesCount,
              alerts_count: alertsCount,
              webhooks_count: webhooksCount,
            },
          };
        } catch (err) {
          request.log.error({ error: err, userId: user.id }, 'Failed to get stats for user');
          throw err;
        }
      });

      return reply.status(200).send({
        success: true,
        data: usersWithStats,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to list users');
      return reply.status(500).send({
        success: false,
        error: 'Failed to list users',
      });
    }
  });

  /**
   * DELETE /api/admin/users/:id - Delete a user (admin only)
   */
  fastify.delete('/users/:id', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Delete a user and all their data (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'number' },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const adminId = request.user!.id;

      // Prevent deleting yourself
      if (id === adminId) {
        return reply.status(403).send({
          success: false,
          error: 'Cannot delete yourself',
          message: 'You cannot delete your own account',
        });
      }

      // Check if user exists
      const user = store.getUserById(id);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Check if this is the last admin
      if (user.is_admin) {
        const allUsers = store.getAllUsers();
        const adminCount = allUsers.filter(u => u.is_admin).length;
        
        if (adminCount <= 1) {
          return reply.status(400).send({
            success: false,
            error: 'Cannot delete last admin',
            message: 'You cannot delete the last administrator account',
          });
        }
      }

      // Delete user (CASCADE will handle rules, alerts, webhooks)
      const deleted = store.deleteUser(id);

      if (!deleted) {
        return reply.status(500).send({
          success: false,
          error: 'Failed to delete user',
        });
      }

      // Log admin action
      store.logAdminAction(adminId, 'delete_user', id, `Deleted user ${user.username} (${user.email})`);

      return reply.status(200).send({
        success: true,
        message: `User ${user.username} deleted successfully`,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to delete user');
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete user',
      });
    }
  });

  /**
   * PATCH /api/admin/users/:id/admin - Toggle admin status (admin only)
   */
  fastify.patch('/users/:id/admin', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Toggle admin status for a user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'number' },
        },
      },
      body: {
        type: 'object',
        required: ['is_admin'],
        properties: {
          is_admin: { type: 'boolean' },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = request.params as { id: number };
      const { is_admin } = request.body as { is_admin: boolean };
      const adminId = request.user!.id;

      // Prevent modifying your own admin status
      if (id === adminId) {
        return reply.status(403).send({
          success: false,
          error: 'Cannot modify your own admin status',
          message: 'You cannot change your own administrator privileges',
        });
      }

      // Check if user exists
      const user = store.getUserById(id);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // If removing admin, check if this is the last admin
      if (user.is_admin && !is_admin) {
        const allUsers = store.getAllUsers();
        const adminCount = allUsers.filter(u => u.is_admin).length;
        
        if (adminCount <= 1) {
          return reply.status(400).send({
            success: false,
            error: 'Cannot remove last admin',
            message: 'You cannot remove administrator privileges from the last admin',
          });
        }
      }

      // Toggle admin status
      const updated = store.toggleUserAdmin(id, is_admin);

      if (!updated) {
        return reply.status(500).send({
          success: false,
          error: 'Failed to update admin status',
        });
      }

      // Log admin action
      const action = is_admin ? 'grant_admin' : 'revoke_admin';
      const details = `${is_admin ? 'Granted' : 'Revoked'} admin privileges for ${user.username}`;
      store.logAdminAction(adminId, action, id, details);

      return reply.status(200).send({
        success: true,
        message: `Admin status updated for ${user.username}`,
        data: { is_admin },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to toggle admin status');
      return reply.status(500).send({
        success: false,
        error: 'Failed to update admin status',
      });
    }
  });

  /**
   * GET /api/admin/stats - Get global statistics (admin only)
   */
  fastify.get('/stats', {
    preHandler: [fastify.requireAdmin],
  }, async (request, reply) => {
    try {
      const stats = store.getGlobalStats();

      return reply.status(200).send({
        success: true,
        data: stats,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get global stats');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve statistics',
      });
    }
  });

  /**
   * GET /api/admin/logs - Get admin action logs (admin only)
   */
  fastify.get('/logs', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Get admin action logs (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'number', default: 50 },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { limit = 50 } = request.query as { limit?: number };
      const logs = store.getAdminLogs(limit);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get admin logs');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve logs',
      });
    }
  });
}
