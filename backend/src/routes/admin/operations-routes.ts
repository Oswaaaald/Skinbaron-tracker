import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getScheduler } from '../../lib/scheduler.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { appConfig } from '../../lib/config.js';
import { captureException, verifySentryConnection } from '../../lib/sentry.js';
import {
  AdminUserParamsSchema,
  AdminAuditQuerySchema,
  AdminLogsQuerySchema,
  AdminUserAuditParamsSchema,
  AdminUserAuditQuerySchema,
  AdminSearchQuerySchema,
} from '../../database/schemas.js';

type RegisterAdminOperationalRoutesOptions = {
  adminWriteRateLimit: {
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

export function registerAdminOperationalRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminOperationalRoutesOptions,
): void {
  const scheduler = getScheduler();

  /**
   * GET /api/admin/stats - Get global statistics (admin only)
   */
  fastify.get('/stats', {
    schema: {
      description: 'Get global statistics (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                users: { type: 'number' },
                admins: { type: 'number' },
                rules: { type: 'number' },
                enabled_rules: { type: 'number' },
                alerts: { type: 'number' },
                webhooks: { type: 'number' },
              },
              additionalProperties: true,
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const stats = await store.audit.getGlobalStats();

      return reply.status(200).send({
        success: true,
        data: {
          ...stats,
          sentryEnabled: !!appConfig.SENTRY_DSN,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get global stats');
    }
  });

  /**
   * GET /api/admin/pending-users - Get users pending approval (admin only)
   */
  fastify.get('/pending-users', {
    schema: {
      description: 'Get users pending approval (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
      const pendingUsers = await store.users.findPendingUsers();

      return reply.status(200).send({
        success: true,
        data: pendingUsers.map((u) => ({
          id: u.id,
          username: u.username,
          email: u.email,
          created_at: u.created_at,
        })),
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get pending users');
    }
  });

  /**
   * POST /api/admin/approve-user/:id - Approve a pending user (admin only)
   */
  fastify.post('/approve-user/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Approve a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
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
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);

      // Check user exists and isn't already approved
      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }
      if (user.is_approved) {
        throw Errors.badRequest('User is already approved');
      }

      const success = await store.users.approveUser(id);

      if (!success) {
        throw Errors.notFound('User');
      }

      const adminId = getAuthUser(request).id;
      const admin = await store.users.findById(adminId);

      // Log admin action
      await store.audit.logAdminAction(adminId, 'approve_user', id, `Approved user ${user.username} (${user.email})`);

      // Create audit log
      await store.audit.createLog(
        id,
        'user_approved',
        JSON.stringify({
          approved_by_admin_id: adminId,
          admin_username: admin?.username,
        }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: 'User approved successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Approve user');
    }
  });

  /**
   * POST /api/admin/reject-user/:id - Reject (delete) a pending user (admin only)
   */
  fastify.post('/reject-user/:id', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Reject and delete a pending user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'integer', minimum: 1 },
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
      const { id } = validateWithZod(AdminUserParamsSchema, request.params);

      // Verify user exists and is actually pending approval
      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }
      if (user.is_approved) {
        throw Errors.forbidden('Only pending users can be rejected. Use the delete endpoint for approved users.');
      }

      // Log admin action BEFORE deleting so the FK to target_user_id is still valid
      await store.audit.logAdminAction(getAuthUser(request).id, 'reject_user', id, `Rejected user ${user.username} (${user.email})`);

      const success = await store.users.rejectUser(id);

      if (!success) {
        throw Errors.notFound('User');
      }

      return reply.status(200).send({
        success: true,
        message: 'User rejected and deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Reject user');
    }
  });

  /**
   * POST /api/admin/scheduler/force-run - Force scheduler to run immediately (admin only)
   */
  fastify.post('/scheduler/force-run', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Force the scheduler to run immediately (bypasses cron schedule) - Admin only',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
      await store.audit.logAdminAction(getAuthUser(request).id, 'force_scheduler', null, 'Manually triggered scheduler run');

      return reply.status(200).send({
        success: true,
        message: 'Scheduler executed successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Force scheduler run');
    }
  });

  /**
   * GET /api/admin/audit-logs/:userId - Get audit logs for a specific user (admin only)
   */
  fastify.get('/audit-logs/:userId', {
    schema: {
      description: 'Get security audit logs for a specific user (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: {
          userId: { type: 'integer', minimum: 1 },
        },
        required: ['userId'],
      },
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 500 },
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
      const { userId } = validateWithZod(AdminUserAuditParamsSchema, request.params);
      const { limit } = validateWithZod(AdminUserAuditQuerySchema, request.query);

      const user = await store.users.findById(userId);
      if (!user) {
        throw Errors.notFound('User');
      }

      const logs = await store.audit.getLogsByUserId(userId, limit);

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
      return handleRouteError(error, request, reply, 'Get user audit logs');
    }
  });

  /**
   * GET /api/admin/audit-logs - Get all audit logs (admin only)
   */
  fastify.get('/audit-logs', {
    schema: {
      description: 'Get all security audit logs (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 1000 },
          event_type: { type: 'string', maxLength: 50 },
          user_id: { type: 'integer', minimum: 1 },
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
      const { limit, event_type, user_id } = validateWithZod(AdminAuditQuerySchema, request.query);

      const logs = await store.audit.getAllLogs(limit, event_type, user_id);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get audit logs');
    }
  });

  /**
   * GET /api/admin/admin-logs - Get admin action logs (super admin only)
   */
  fastify.get('/admin-logs', {
    preHandler: [fastify.requireSuperAdmin],
    schema: {
      description: 'Get admin action logs (super admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'integer', minimum: 1, default: 100, maximum: 1000 },
          action: { type: 'string', maxLength: 50 },
          admin_id: { type: 'integer', minimum: 1 },
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
                  admin_user_id: { type: 'number' },
                  admin_username: { type: 'string', nullable: true },
                  action: { type: 'string' },
                  target_user_id: { type: 'number', nullable: true },
                  target_username: { type: 'string', nullable: true },
                  details: { type: 'string', nullable: true },
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
      const { limit, action, admin_id } = validateWithZod(AdminLogsQuerySchema, request.query);
      const logs = await store.audit.getAdminLogs(limit, action, admin_id);

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get admin logs');
    }
  });

  /**
   * GET /api/admin/users/search - Search users by username or email
   */
  fastify.get('/users/search', {
    schema: {
      description: 'Search users by username or email (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', minLength: 1, maxLength: 100 },
          admins_only: { type: 'string', enum: ['true', 'false'] },
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
      const { q, admins_only } = validateWithZod(AdminSearchQuerySchema, request.query);
      const users = await store.users.searchUsers(q, admins_only);

      return reply.status(200).send({
        success: true,
        data: users,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Search users');
    }
  });

  /**
   * POST /api/admin/test-sentry - Trigger a test error for Sentry verification (super admin only)
   */
  fastify.post('/test-sentry', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    preHandler: [fastify.requireSuperAdmin],
    schema: {
      description: 'Trigger a test error that is captured by Sentry - Super Admin only',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            verified: { type: 'boolean' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      if (!appConfig.SENTRY_DSN) {
        throw Errors.badRequest('Sentry is not configured — set SENTRY_DSN to enable');
      }

      // Verify DSN connectivity before sending the test error
      const verification = await verifySentryConnection();
      if (!verification.ok) {
        throw Errors.badRequest(verification.reason ?? 'Sentry DSN verification failed');
      }

      const testError = new Error('Sentry test error — triggered by admin');
      captureException(testError, { triggeredBy: getAuthUser(request).id });

      await store.audit.logAdminAction(
        getAuthUser(request).id,
        'test_sentry',
        null,
        'Triggered a Sentry test error',
      );

      return reply.status(200).send({
        success: true,
        message: 'Test error sent to Sentry',
        verified: true,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Test Sentry');
    }
  });
}
