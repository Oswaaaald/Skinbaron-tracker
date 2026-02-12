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
  item_name: z.string().optional(),
  sort_by: z.enum(['date', 'price_asc', 'price_desc', 'wear_asc', 'wear_desc']).optional(),
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
          item_name: { type: 'string', description: 'Filter by item name (partial match)' },
          sort_by: { type: 'string', enum: ['date', 'price_asc', 'price_desc', 'wear_asc', 'wear_desc'], description: 'Sort order' },
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
      const query = validateWithZod(AlertsQuerySchema, request.query);
      
      // Get user's alerts with pagination and filters
      let alerts = store.getAlertsByUserId(
        request.user!.id, 
        query.limit, 
        query.offset,
        {
          itemName: query.item_name,
          sortBy: query.sort_by,
        }
      );
      
      // Apply additional filters if provided
      if (query.rule_id !== undefined) {
        // Ensure the rule belongs to the user
        const rule = store.getRuleById(query.rule_id);
        if (!rule || rule.user_id !== request.user!.id) {
          throw new AppError(403, 'You can only access alerts for your own rules', 'ACCESS_DENIED');
        }
        alerts = alerts.filter(alert => alert.rule_id === query.rule_id);
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
   * GET /alerts/items - Get unique item names for filtering
   */
  fastify.get('/items', {
    schema: {
      description: 'Get unique item names from user alerts for filtering',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: { type: 'string' },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const itemNames = store.getUniqueAlertItemNames(request.user!.id);
      
      return reply.status(200).send({
        success: true,
        data: itemNames,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get item names');
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
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const stats = store.getUserStats(request.user!.id);
      
      return reply.status(200).send({
        success: true,
        data: stats,
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