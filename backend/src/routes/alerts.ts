import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { store } from '../database/index.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';

// Query parameters schemas
const AlertsQuerySchema = z.object({
  limit: z.string().default('50').transform(val => parseInt(val, 10)),
  offset: z.string().default('0').transform(val => parseInt(val, 10)),
  rule_id: z.string().transform(val => parseInt(val, 10)).optional(),
  alert_type: z.enum(['match', 'best_deal', 'new_item']).optional(),
});

const AlertParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

// Route handlers
const alertsRoutes: FastifyPluginAsync = async (fastify) => {

  /**
   * GET /alerts - Get user's alerts with pagination
   */
  fastify.get('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get user alerts with pagination and filtering',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
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
   * GET /alerts/:id - Get a specific alert (user-owned only)
   */
  fastify.get('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get a specific alert by ID',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
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
        },
        404: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            error: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { id } = validateWithZod(AlertParamsSchema, request.params, 'alert params');
      const alert = store.getAlertByIdForUser(id, request.user!.id);
      
      if (!alert) {
        throw new AppError(404, 'Alert not found', 'NOT_FOUND');
      }
      
      return reply.status(200).send({
        success: true,
        data: alert,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get alert');
    }
  });

  /**
   * GET /alerts/stats - Get user alert statistics
   */
  fastify.get('/stats', {
    preHandler: [fastify.authenticate],
    logLevel: 'warn', // Reduce logging for this frequent endpoint
    schema: {
      description: 'Get user alert statistics',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
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
   * POST /alerts/cleanup - Cleanup user's old alerts (older than 7 days)
   */
  fastify.post('/cleanup', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Cleanup user\'s old alerts (older than 7 days)',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const userId = request.user!.id;
      const deletedCount = store.cleanupUserOldAlerts(userId);
      
      request.log.info(`User ${userId} cleaned up ${deletedCount} old alerts`);
      
      return reply.status(200).send({
        success: true,
        data: {
          deletedCount,
          message: `Successfully deleted ${deletedCount} of your old alerts (7+ days)`,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to cleanup user alerts');
    }
  });

  /**
   * POST /alerts/clear-all - Delete all user alerts
   */
  fastify.post('/clear-all', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Delete all user alerts',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
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

  /**
   * GET /alerts/recent - Get user's recent alerts (last 24h)
   */
  fastify.get('/recent', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get user alerts from the last 24 hours',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'string', default: '20' },
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
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const query = validateWithZod(
        z.object({
          limit: z.coerce.number().default(20),
        }),
        request.query,
        'recent alerts query'
      );
      
      // Get user's alerts and filter for last 24h
      const userAlerts = store.getAlertsByUserId(request.user!.id, 1000, 0);
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      const recentAlerts = userAlerts
        .filter(alert => new Date(alert.sent_at!) > oneDayAgo)
        .slice(0, query.limit);
      
      return reply.status(200).send({
        success: true,
        data: recentAlerts,
        count: recentAlerts.length,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get recent alerts');
    }
  });

  /**
   * GET /alerts/by-rule/:ruleId - Get alerts for a specific user rule
   */
  fastify.get('/by-rule/:ruleId', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get all alerts for a specific user rule',
      tags: ['Alerts'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        properties: {
          ruleId: { type: 'string' },
        },
      },
      querystring: {
        type: 'object',
        properties: {
          limit: { type: 'string', default: '50' },
          offset: { type: 'string', default: '0' },
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
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { ruleId } = validateWithZod(
        z.object({
          ruleId: z.string().transform(val => parseInt(val, 10)),
        }),
        request.params,
        'rule params'
      );
      
      const { limit, offset } = validateWithZod(
        z.object({
          limit: z.coerce.number().default(50),
          offset: z.coerce.number().default(0),
        }),
        request.query,
        'pagination query'
      );
      
      // Ensure rule belongs to the user before getting alerts
      const rule = store.getRuleById(ruleId);
      if (!rule) {
        throw new AppError(404, 'Rule not found', 'NOT_FOUND');
      }

      if (rule.user_id !== request.user!.id) {
        throw new AppError(403, 'You can only access alerts for your own rules', 'ACCESS_DENIED');
      }
      
      // Get alerts for user's rule
      const ruleAlerts = store.getAlertsByRuleIdForUser(ruleId, request.user!.id, limit, offset);
      
      return reply.status(200).send({
        success: true,
        data: ruleAlerts,
        count: ruleAlerts.length,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Failed to get alerts by rule');
    }
  });
};

export default alertsRoutes;