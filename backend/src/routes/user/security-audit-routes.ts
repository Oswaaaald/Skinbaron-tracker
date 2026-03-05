import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { UserAuditQuerySchema } from '../../database/schemas.js';

export function registerUserSecurityAuditRoutes(fastify: FastifyInstance): void {
  fastify.get('/audit-logs', {
    schema: {
      description: 'Get security audit logs for current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
      const { limit } = validateWithZod(UserAuditQuerySchema, request.query);

      const allLogs = await store.audit.getLogsByUserId(userId, limit);
      const ADMIN_ONLY_EVENTS = new Set([
        'account_restricted',
        'account_unrestricted',
        'sanction_deleted',
        '2fa_reset_by_admin',
        'passkeys_reset_by_admin',
        'sessions_reset_by_admin',
      ]);
      const logs = allLogs.filter((log) => !ADMIN_ONLY_EVENTS.has(log.event_type));

      return reply.status(200).send({
        success: true,
        data: logs,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get audit logs');
    }
  });
}
