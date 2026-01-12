import { FastifyInstance } from 'fastify';
import { getStore } from '../lib/store.js';
import { getScheduler } from '../lib/scheduler.js';
import { getClientIp } from '../lib/middleware.js';

/**
 * Admin routes - All routes require admin privileges
 */
export default async function adminRoutes(fastify: FastifyInstance) {
  const store = getStore();
  const scheduler = getScheduler();

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

      // Only super admins can delete admins
      if (user.is_admin) {
        const currentAdmin = store.getUserById(adminId);
        if (!currentAdmin?.is_super_admin) {
          return reply.status(403).send({
            success: false,
            error: 'Permission denied',
            message: 'Only super administrators can delete other administrators',
          });
        }

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

      // Create audit log
      store.createAuditLog(
        id,
        'user_deleted',
        JSON.stringify({ 
          deleted_by_admin_id: adminId,
          username: user.username,
          email: user.email 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

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

      // Only super admins can grant or revoke admin status to/from admins
      if (user.is_admin || is_admin) {
        const currentAdmin = store.getUserById(adminId);
        if (!currentAdmin?.is_super_admin) {
          return reply.status(403).send({
            success: false,
            error: 'Permission denied',
            message: 'Only super administrators can manage admin privileges',
          });
        }
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

      // Create audit log
      const eventType = is_admin ? 'user_promoted' : 'user_demoted';
      store.createAuditLog(
        id,
        eventType,
        JSON.stringify({ 
          admin_id: adminId,
          is_admin 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

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

  /**
   * GET /api/admin/pending-users - Get users pending approval (admin only)
   */
  fastify.get('/pending-users', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Get users pending approval (admin only)',
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
      const pendingUsers = store.getPendingUsers();

      return reply.status(200).send({
        success: true,
        data: pendingUsers,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get pending users');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve pending users',
      });
    }
  });

  /**
   * POST /api/admin/approve-user/:id - Approve a pending user (admin only)
   */
  fastify.post('/approve-user/:id', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Approve a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'number' },
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
      const { id } = request.params as { id: number };
      const success = store.approveUser(id);

      if (!success) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Log admin action
      store.logAdminAction(request.user!.id, 'APPROVE_USER', id, `Approved user ID ${id}`);

      // Create audit log
      store.createAuditLog(
        id,
        'user_approved',
        JSON.stringify({ 
          approved_by_admin_id: request.user!.id 
        }),
        getClientIp(request),
        request.headers['user-agent']
      );

      return reply.status(200).send({
        success: true,
        message: 'User approved successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to approve user');
      return reply.status(500).send({
        success: false,
        error: 'Failed to approve user',
      });
    }
  });

  /**
   * POST /api/admin/reject-user/:id - Reject (delete) a pending user (admin only)
   */
  fastify.post('/reject-user/:id', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Reject and delete a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'number' },
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
      const { id } = request.params as { id: number };
      const success = store.rejectUser(id);

      if (!success) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      // Log admin action
      store.logAdminAction(request.user!.id, 'REJECT_USER', id, `Rejected user ID ${id}`);

      return reply.status(200).send({
        success: true,
        message: 'User rejected and deleted successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to reject user');
      return reply.status(500).send({
        success: false,
        error: 'Failed to reject user',
      });
    }
  });

  /**
   * POST /api/admin/scheduler/force-run - Force scheduler to run immediately (super admin only)
   */
  fastify.post('/scheduler/force-run', {
    preHandler: [fastify.requireSuperAdmin],
    schema: {
      description: 'Force the scheduler to run immediately (bypasses cron schedule) - Super Admin only',
      tags: ['Admin'],
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
      // Force the scheduler to execute immediately
      await scheduler.forceRun();

      // Log admin action
      store.logAdminAction(request.user!.id, 'FORCE_SCHEDULER', null, 'Manually triggered scheduler run');

      return reply.status(200).send({
        success: true,
        message: 'Scheduler executed successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to force scheduler run');
      return reply.status(500).send({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to execute scheduler',
      });
    }
  });

  /**
   * GET /api/admin/audit-logs/:userId - Get audit logs for specific user (admin only)
   */
  fastify.get('/audit-logs/:userId', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Get security audit logs for a specific user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        properties: {
          userId: { type: 'number' },
        },
        required: ['userId'],
      },
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
              type: 'object',
              properties: {
                user: {
                  type: 'object',
                  properties: {
                    id: { type: 'number' },
                    username: { type: 'string' },
                    email: { type: 'string' },
                  },
                },
                logs: {
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
      },
    },
  }, async (request, reply) => {
    try {
      const { userId } = request.params as { userId: number };
      const { limit = 100 } = request.query as { limit?: number };

      const user = store.getUserById(userId);
      if (!user) {
        return reply.status(404).send({
          success: false,
          error: 'User not found',
        });
      }

      const logs = store.getAuditLogsByUserId(userId, limit);

      return reply.status(200).send({
        success: true,
        data: {
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
          },
          logs,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get user audit logs');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get audit logs',
      });
    }
  });

  /**
   * GET /api/admin/audit-logs - Get all audit logs (super admin only)
   */
  fastify.get('/audit-logs', {
    preHandler: [fastify.requireSuperAdmin],
    schema: {
      description: 'Get all security audit logs (super admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'number', default: 100, maximum: 1000 },
          event_type: { type: 'string' },
          user_id: { type: 'number' },
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
                  user_id: { type: 'number' },
                  username: { type: 'string', nullable: true },
                  email: { type: 'string', nullable: true },
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
      const { limit = 100, event_type, user_id } = request.query as { limit?: number; event_type?: string; user_id?: number };

      const logs = store.getAllAuditLogs(limit, event_type, user_id);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get all audit logs');
      return reply.status(500).send({
        success: false,
        error: 'Failed to get audit logs',
      });
    }
  });

  /**
   * GET /api/admin/users/search - Search users by username or email
   */
  fastify.get('/users/search', {
    preHandler: [fastify.requireAdmin],
    schema: {
      description: 'Search users by username or email (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', minLength: 1 },
        },
        required: ['q'],
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
                  username: { type: 'string' },
                  email: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { q } = request.query as { q: string };
      const users = store.searchUsers(q);

      return reply.status(200).send({
        success: true,
        data: users,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to search users');
      return reply.status(500).send({
        success: false,
        error: 'Failed to search users',
      });
    }
  });
}
