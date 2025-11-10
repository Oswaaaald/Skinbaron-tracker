import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getStore } from '../lib/store.js';

// Query parameters schemas
const AlertsQuerySchema = z.object({
  limit: z.string().transform(val => parseInt(val, 10)).default('50'),
  offset: z.string().transform(val => parseInt(val, 10)).default('0'),
  rule_id: z.string().transform(val => parseInt(val, 10)).optional(),
  alert_type: z.enum(['match', 'best_deal', 'new_item']).optional(),
});

const AlertParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

// Route handlers
const alertsRoutes: FastifyPluginAsync = async (fastify) => {
  const store = getStore();

  /**
   * GET /alerts - Get user's alerts with pagination
   */
  fastify.get('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get user alerts with pagination and filtering',
      tags: ['Alerts'],
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
      const query = AlertsQuerySchema.parse(request.query);
      
      // Get user's alerts with pagination
      let alerts = store.getAlertsByUserId(request.user!.id, query.limit, query.offset);
      
      // Apply filters if provided
      if (query.rule_id !== undefined) {
        // Ensure the rule belongs to the user
        const rule = store.getRuleById(query.rule_id);
        if (!rule || rule.user_id !== request.user!.id.toString()) {
          return reply.code(403).send({
            success: false,
            error: 'Access denied',
            message: 'You can only access alerts for your own rules',
          });
        }
        alerts = alerts.filter(alert => alert.rule_id === query.rule_id);
      }
      
      if (query.alert_type) {
        alerts = alerts.filter(alert => alert.alert_type === query.alert_type);
      }
      
      return reply.code(200).send({
        success: true,
        data: alerts,
        pagination: {
          limit: query.limit,
          offset: query.offset,
          count: alerts.length,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get alerts');
      
      if (error instanceof z.ZodError) {
        return reply.code(400).send({
          success: false,
          error: 'Validation error',
          details: error.errors,
        });
      }
      
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve alerts',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
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
      const { id } = AlertParamsSchema.parse(request.params);
      const alert = store.getAlertByIdForUser(id, request.user!.id);
      
      if (!alert) {
        return reply.code(404).send({
          success: false,
          error: 'Alert not found',
        });
      }
      
      return reply.code(200).send({
        success: true,
        data: alert,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get alert');
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve alert',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
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
      
      return reply.code(200).send({
        success: true,
        data: {
          ...stats,
          alertsByType,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get alert stats');
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve alert statistics',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /alerts/cleanup - Cleanup user's old alerts (older than 7 days)
   */
  fastify.post('/cleanup', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    try {
      const userId = (request as any).user.id;
      const deletedCount = store.cleanupUserOldAlerts(userId);
      
      request.log.info(`User ${userId} cleaned up ${deletedCount} old alerts`);
      
      return reply.code(200).send({
        success: true,
        data: {
          deletedCount,
          message: `Successfully deleted ${deletedCount} of your old alerts (7+ days)`,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to cleanup user alerts');
      return reply.code(500).send({
        success: false,
        error: 'Failed to cleanup alerts',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /alerts/clear-all - Delete all user alerts
   */
  fastify.post('/clear-all', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    try {
      const userId = (request as any).user.id;
      const deletedCount = store.deleteAllUserAlerts(userId);
      
      request.log.info(`User ${userId} cleared all ${deletedCount} alerts`);
      
      return reply.code(200).send({
        success: true,
        data: {
          deletedCount,
          message: `Successfully deleted all ${deletedCount} of your alerts`,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to clear all user alerts');
      return reply.code(500).send({
        success: false,
        error: 'Failed to clear alerts',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
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
      const query = z.object({
        limit: z.string().transform(val => parseInt(val, 10)).default('20'),
      }).parse(request.query);
      
      // Get user's alerts and filter for last 24h
      const userAlerts = store.getAlertsByUserId(request.user!.id, 1000, 0);
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      const recentAlerts = userAlerts
        .filter(alert => new Date(alert.sent_at!) > oneDayAgo)
        .slice(0, query.limit);
      
      return reply.code(200).send({
        success: true,
        data: recentAlerts,
        count: recentAlerts.length,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get recent alerts');
      
      if (error instanceof z.ZodError) {
        return reply.code(400).send({
          success: false,
          error: 'Validation error',
          details: error.errors,
        });
      }
      
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve recent alerts',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
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
      const { ruleId } = z.object({
        ruleId: z.string().transform(val => parseInt(val, 10)),
      }).parse(request.params);
      
      const { limit, offset } = z.object({
        limit: z.string().transform(val => parseInt(val, 10)).default('50'),
        offset: z.string().transform(val => parseInt(val, 10)).default('0'),
      }).parse(request.query);
      
      // Ensure rule belongs to the user before getting alerts
      const rule = store.getRuleById(ruleId);
      if (!rule) {
        return reply.code(404).send({
          success: false,
          error: 'Rule not found',
        });
      }

      if (rule.user_id !== request.user!.id.toString()) {
        return reply.code(403).send({
          success: false,
          error: 'Access denied',
          message: 'You can only access alerts for your own rules',
        });
      }
      
      // Get alerts for user's rule
      const ruleAlerts = store.getAlertsByRuleIdForUser(ruleId, request.user!.id, limit, offset);
      
      return reply.code(200).send({
        success: true,
        data: ruleAlerts,
        count: ruleAlerts.length,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get alerts by rule');
      
      if (error instanceof z.ZodError) {
        return reply.code(400).send({
          success: false,
          error: 'Validation error',
          details: error.errors,
        });
      }
      
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve alerts for rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
};

export default alertsRoutes;