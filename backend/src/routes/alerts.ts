import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { store } from '../database/index.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';

// Query parameters schemas
const AlertsQuerySchema = z.object({
  limit: z.string().default('50').transform(val => {
    const num = parseInt(val, 10);
    return Math.min(num, 500); // Max 500 alerts per request
  }),
  offset: z.string().default('0').transform(val => parseInt(val, 10)),
  rule_id: z.string().transform(val => parseInt(val, 10)).optional(),
  alert_type: z.enum(['match', 'best_deal', 'new_item']).optional(),
});

// Route handlers
const alertsRoutes: FastifyPluginAsync = async (fastify) => {
  // Local hook for defense in depth - ensures all routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);

  /**
   * GET /alerts - Get user's alerts with pagination
   */
  fastify.get('/', {
    schema: {
      description: 'Get user alerts with pagination and filtering',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'string', default: '50' },
          offset: { type: 'string', default: '0' },
          rule_id: { type: 'string' },
          alert_type: { type: 'string', enum: ['match', 'best_deal', 'new_item'] },
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
                  rule_id: { type: 'number' },
                  sale_id: { type: 'string' },
                  item_name: { type: 'string' },
                  price: { type: 'number' },
                  wear_value: { type: 'number', nullable: true },
                  stattrak: { type: 'boolean' },
                  souvenir: { type: 'boolean' },
                  skin_url: { type: 'string' },
                  alert_type: { type: 'string' },
                  sent_at: { type: 'string' },
                },
              },
            },
            pagination: {
              type: 'object',
              properties: {
                limit: { type: 'number' },
                offset: { type: 'number' },
                count: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const query = validateWithZod(AlertsQuerySchema, request.query, 'alerts query');
      
      // Get user's alerts with pagination
      let alerts = store.getAlertsByUserId(request.user!.id, query.limit, query.offset);
      
      // Apply filters if provided
      if (query.rule_id !== undefined) {
        // Ensure the rule belongs to the user
        const rule = store.getRuleById(query.rule_id);
        if (!rule || rule.user_id !== request.user!.id) {
          throw new AppError(403, 'You can only access alerts for your own rules', 'ACCESS_DENIED');
        }
        alerts = alerts.filter(alert => alert.rule_id === query.rule_id);
      }
      
      if (query.alert_type) {
        alerts = alerts.filter(alert => alert.alert_type === query.alert_type);
      }
      
      return reply.status(200).send({
        success: true,
        data: alerts,
        pagination: {
          limit: query.limit,
          offset: query.offset,
          count: alerts.length,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get alerts');
    }
  });

  /**
   * GET /alerts/stats - Get user alert statistics
   */
  fastify.get('/stats', {
    logLevel: 'warn', // Reduce logging for this frequent endpoint
    schema: {
      description: 'Get user alert statistics',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                totalRules: { type: 'number' },
                enabledRules: { type: 'number' },
                totalAlerts: { type: 'number' },
                todayAlerts: { type: 'number' },
                alertsByType: {
                  type: 'object',
                  properties: {
                    match: { type: 'number' },
                    best_deal: { type: 'number' },
                    new_item: { type: 'number' },
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
      const stats = store.getUserStats(request.user!.id);
      
      // Get user alerts by type
      const userAlerts = store.getAlertsByUserId(request.user!.id, 1000, 0); // Get a large batch for stats
      const alertsByType = {
        match: userAlerts.filter(alert => alert.alert_type === 'match').length,
        best_deal: userAlerts.filter(alert => alert.alert_type === 'best_deal').length,
        new_item: userAlerts.filter(alert => alert.alert_type === 'new_item').length,
      };
      
      return reply.status(200).send({
        success: true,
        data: {
          ...stats,
          alertsByType,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get alert stats');
    }
  });

  /**
   * POST /alerts/clear-all - Delete all user alerts
   */
  fastify.post('/clear-all', {
    schema: {
      description: 'Delete all user alerts',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = request.user!.id;
      const deletedCount = store.deleteAllUserAlerts(userId);
      
      request.log.info(`User ${userId} cleared all ${deletedCount} alerts`);
      
      return reply.status(200).send({
        success: true,
        data: {
          deletedCount,
          message: `Successfully deleted all ${deletedCount} of your alerts`,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to clear all user alerts');
    }
  });
};

export default alertsRoutes;