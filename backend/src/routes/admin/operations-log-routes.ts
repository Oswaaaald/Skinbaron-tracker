import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import {
  AdminAuditQuerySchema,
  AdminLogsQuerySchema,
  AdminUserAuditParamsSchema,
  AdminUserAuditQuerySchema,
  AdminSearchQuerySchema,
} from '../../database/validation-schemas.js';

export function registerAdminOperationalLogRoutes(fastify: FastifyInstance): void {
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
}
