import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { store } from '../database/index.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { getAuthUser } from '../lib/middleware.js';

// Query parameters schemas
const AlertsQuerySchema = z.object({
  limit: z.string().default('0').transform(val => {
    const num = parseInt(val, 10);
    return num > 0 ? num : 0; // 0 = no limit (return all)
  }),
  offset: z.string().default('0').transform(val => parseInt(val, 10)),
  rule_id: z.string().transform(val => parseInt(val, 10)).optional(),
  item_name: z.string().optional(),
  sort_by: z.enum(['date', 'price_asc', 'price_desc', 'wear_asc', 'wear_desc']).optional(),
});

// Route handlers
export default async function alertsRoutes(fastify: FastifyInstance) {
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
          limit: { type: 'string', default: '0', description: '0 = no limit (return all alerts)' },
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
                  has_stickers: { type: 'boolean' },
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
                total: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const query = validateWithZod(AlertsQuerySchema, request.query);
      
      // Validate rule ownership if rule_id filter is provided
      if (query.rule_id !== undefined) {
        const rule = await store.getRuleById(query.rule_id);
        if (!rule || rule.user_id !== getAuthUser(request).id) {
          throw new AppError(403, 'You can only access alerts for your own rules', 'ACCESS_DENIED');
        }
      }

      // Get total count for pagination metadata
      const total = await store.alerts.countByUserId(getAuthUser(request).id);

      // Get user's alerts with filters (limit=0 means return all)
      const alerts = await store.getAlertsByUserId(
        getAuthUser(request).id, 
        query.limit, 
        query.offset,
        {
          ruleId: query.rule_id,
          itemName: query.item_name,
          sortBy: query.sort_by,
        }
      );
      
      return reply.status(200).send({
        success: true,
        data: alerts,
        pagination: {
          limit: query.limit,
          offset: query.offset,
          count: alerts.length,
          total,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get alerts');
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
      const itemNames = await store.getUniqueAlertItemNames(getAuthUser(request).id);
      
      return reply.status(200).send({
        success: true,
        data: itemNames,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get item names');
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
      const stats = await store.getUserStats(getAuthUser(request).id);
      
      return reply.status(200).send({
        success: true,
        data: stats,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get alert stats');
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
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                deletedCount: { type: 'number' },
                message: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const deletedCount = await store.deleteAllUserAlerts(userId);
      
      request.log.info(`User ${userId} cleared all ${deletedCount} alerts`);
      
      return reply.status(200).send({
        success: true,
        data: {
          deletedCount,
          message: `Successfully deleted all ${deletedCount} of your alerts`,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Clear alerts');
    }
  });
}