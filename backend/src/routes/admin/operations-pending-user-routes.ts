import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { AdminUserParamsSchema } from '../../database/schemas.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminOperationalPendingUserRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
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

      await store.audit.logAdminAction(adminId, 'approve_user', id, `Approved user ${user.username} (${user.email})`);

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

      const user = await store.users.findById(id);
      if (!user) {
        throw Errors.notFound('User');
      }
      if (user.is_approved) {
        throw Errors.forbidden('Only pending users can be rejected. Use the delete endpoint for approved users.');
      }

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
}
