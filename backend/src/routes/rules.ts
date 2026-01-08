import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getStore, RuleSchema } from '../lib/store.js';
import { getScheduler } from '../lib/scheduler.js';
import { getNotificationService } from '../lib/notifier.js';

// Extend FastifyInstance type for authenticate
declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: any, reply: any) => Promise<void>;
  }
}

// Request/Response schemas
/**
 * Rule request schemas
 */
const CreateRuleRequestSchema = RuleSchema.omit({ 
  id: true, 
  created_at: true, 
  updated_at: true 
});

// Use the same schema for updates to maintain consistency
const UpdateRuleRequestSchema = CreateRuleRequestSchema;

const RuleParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

const TestRuleRequestSchema = z.object({
  webhook_test: z.boolean().optional().default(false),
  webhook_only: z.boolean().optional().default(false),
});

// Route handlers
const rulesRoutes: FastifyPluginAsync = async (fastify) => {
  const store = getStore();
  const scheduler = getScheduler();
  const notificationService = getNotificationService();

  /**
   * GET /rules - Get all rules for authenticated user
   */
  fastify.get('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get all alert rules for authenticated user',
      tags: ['Rules'],
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
                  user_id: { type: 'string' },
                  search_item: { type: 'string' },
                  min_price: { type: 'number', nullable: true },
                  max_price: { type: 'number', nullable: true },
                  min_wear: { type: 'number', nullable: true },
                  max_wear: { type: 'number', nullable: true },
                  stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                  souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                  allow_stickers: { type: 'boolean' },
                  webhook_ids: { type: 'array', items: { type: 'number' } },
                  enabled: { type: 'boolean' },
                  created_at: { type: 'string' },
                  updated_at: { type: 'string' },
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
      // Get rules only for the authenticated user
      const rules = store.getRulesByUserId(request.user!.id);
      
      return reply.status(200).send({
        success: true,
        data: rules,
        count: rules.length,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get rules');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve rules',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /rules - Create a new rule
   */
  fastify.post('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Create a new alert rule for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        required: ['search_item'],
        properties: {
          search_item: { type: 'string', minLength: 1 },
          min_price: { type: 'number', minimum: 0 },
          max_price: { type: 'number', minimum: 0 },
          min_wear: { type: 'number', minimum: 0, maximum: 1 },
          max_wear: { type: 'number', minimum: 0, maximum: 1 },
          stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          allow_stickers: { type: 'boolean' },
          webhook_ids: { type: 'array', items: { type: 'number' }, minItems: 0, maxItems: 10 },
          enabled: { type: 'boolean', default: true },
        },
      },
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                user_id: { type: 'string' },
                search_item: { type: 'string' },
                min_price: { type: 'number', nullable: true },
                max_price: { type: 'number', nullable: true },
                min_wear: { type: 'number', nullable: true },
                max_wear: { type: 'number', nullable: true },
                stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                allow_stickers: { type: 'boolean' },
                webhook_ids: { type: 'array', items: { type: 'number' } },
                enabled: { type: 'boolean' },
                created_at: { type: 'string' },
                updated_at: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      // Parse body but add user_id from authenticated user
      const bodyData = request.body as any;
      
      const ruleData = CreateRuleRequestSchema.parse({
        ...bodyData,
        user_id: request.user!.id.toString(), // Convert to string for compatibility
      });
      
      // Validate webhook_ids if provided - must belong to user
      if (ruleData.webhook_ids && ruleData.webhook_ids.length > 0) {
        const userWebhooks = store.getUserWebhooksByUserId(request.user!.id);
        const userWebhookIds = userWebhooks.map(w => w.id);
        
        const invalidWebhooks = ruleData.webhook_ids.filter((id: number) => !userWebhookIds.includes(id));
        if (invalidWebhooks.length > 0) {
          return reply.status(400).send({
            success: false,
            error: 'Invalid webhook IDs',
            message: `Webhook IDs ${invalidWebhooks.join(', ')} do not exist or do not belong to you. Please check that these webhooks haven't been deleted.`,
          });
        }
      } else {
        // If no webhook IDs provided, set to empty array
        ruleData.webhook_ids = [];
      }

      const rule = store.createRule(ruleData);
      
      request.log.info(`Created rule ${rule.id} for user ${rule.user_id}`);
      
      return reply.status(201).send({
        success: true,
        data: rule,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to create rule');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to create rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /rules/:id - Get a specific rule
   */
  fastify.get('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get a specific rule by ID (user-owned)',
      tags: ['Rules'],
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
                user_id: { type: 'string' },
                search_item: { type: 'string' },
                min_price: { type: 'number', nullable: true },
                max_price: { type: 'number', nullable: true },
                min_wear: { type: 'number', nullable: true },
                max_wear: { type: 'number', nullable: true },
                stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                allow_stickers: { type: 'boolean' },
                webhook_ids: { type: 'array', items: { type: 'number' } },
                enabled: { type: 'boolean' },
                created_at: { type: 'string' },
                updated_at: { type: 'string' },
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
      const { id } = RuleParamsSchema.parse(request.params);
      const rule = store.getRuleById(id);
      
      if (!rule) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }

      // Verify user owns this rule
      if (rule.user_id !== request.user!.id.toString()) {
        return reply.status(403).send({
          success: false,
          error: 'Access denied',
          message: 'You can only access your own rules',
        });
      }
      
      return reply.status(200).send({
        success: true,
        data: rule,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get rule');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * PUT /rules/:id - Update a rule
   */
  fastify.put('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Update an existing rule (user-owned)',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        required: ['search_item'],
        properties: {
          search_item: { type: 'string', minLength: 1 },
          min_price: { type: 'number', minimum: 0, nullable: true },
          max_price: { type: 'number', minimum: 0, nullable: true },
          min_wear: { type: 'number', minimum: 0, maximum: 1, nullable: true },
          max_wear: { type: 'number', minimum: 0, maximum: 1, nullable: true },
          stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          allow_stickers: { type: 'boolean' },
          webhook_ids: { type: 'array', items: { type: 'number' }, minItems: 0, maxItems: 10 },
          enabled: { type: 'boolean', default: true },
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
                user_id: { type: 'string' },
                search_item: { type: 'string' },
                min_price: { type: 'number', nullable: true },
                max_price: { type: 'number', nullable: true },
                min_wear: { type: 'number', nullable: true },
                max_wear: { type: 'number', nullable: true },
                stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
                allow_stickers: { type: 'boolean' },
                webhook_ids: { type: 'array', items: { type: 'number' } },
                enabled: { type: 'boolean' },
                created_at: { type: 'string' },
                updated_at: { type: 'string' },
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
      const { id } = RuleParamsSchema.parse(request.params);
      
      // Check if rule exists and user owns it
      const existingRule = store.getRuleById(id);
      if (!existingRule) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }

      if (existingRule.user_id !== request.user!.id.toString()) {
        return reply.status(403).send({
          success: false,
          error: 'Access denied',
          message: 'You can only update your own rules',
        });
      }

      // Parse body but add user_id from authenticated user (same as create)
      const bodyData = request.body as any;
      
      const updates = UpdateRuleRequestSchema.parse({
        ...bodyData,
        user_id: request.user!.id.toString(), // Convert to string for compatibility
      });
      
      // Validate webhook_ids - filter out deleted webhooks automatically
      const userWebhooks = store.getUserWebhooksByUserId(request.user!.id);
      const userWebhookIds = userWebhooks.map(w => w.id);
      
      if (updates.webhook_ids !== undefined) {
        if (updates.webhook_ids.length === 0) {
          // Allow empty webhook arrays - rule will be created/updated without notifications
          // No validation needed
        } else {
          // Store original count for logging
          const originalCount = updates.webhook_ids.length;
          
          // Filter out webhook IDs that no longer exist or don't belong to user
          const validWebhookIds = updates.webhook_ids.filter((id: number) => userWebhookIds.includes(id));
          
          // Update with only the valid webhook IDs (could be empty after filtering)
          updates.webhook_ids = validWebhookIds;
          
          // Log if some webhooks were filtered out
          if (originalCount > validWebhookIds.length) {
            const removedCount = originalCount - validWebhookIds.length;
            request.log.info(`Filtered out ${removedCount} deleted webhook(s) from rule update`);
          }
        }
      }
      
      const rule = store.updateRule(id, updates);
      
      if (!rule) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }
      
      request.log.info(`Updated rule ${rule.id}`);
      
      return reply.status(200).send({
        success: true,
        data: rule,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to update rule');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to update rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * DELETE /rules/:id - Delete a rule
   */
  fastify.delete('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Delete a rule (user-owned)',
      security: [{ bearerAuth: [] }],
      tags: ['Rules'],
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
            message: { type: 'string' },
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
      const { id } = RuleParamsSchema.parse(request.params);
      
      // Check if rule exists and user owns it
      const existingRule = store.getRuleById(id);
      if (!existingRule) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }

      if (existingRule.user_id !== request.user!.id.toString()) {
        return reply.status(403).send({
          success: false,
          error: 'Access denied',
          message: 'You can only delete your own rules',
        });
      }

      const deleted = store.deleteRule(id);
      
      if (!deleted) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }
      
      request.log.info(`Deleted rule ${id}`);
      
      return reply.status(200).send({
        success: true,
        message: 'Rule deleted successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to delete rule');
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * POST /rules/:id/test - Test a rule
   */
  fastify.post('/:id/test', {
    schema: {
      description: 'Test a rule without creating alerts',
      tags: ['Rules'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        properties: {
          webhook_test: { type: 'boolean', default: false },
          webhook_only: { type: 'boolean', default: false },
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
                matches: { type: 'array' },
                matchCount: { type: 'number' },
                webhookTest: { type: 'boolean' },
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
      const { id } = RuleParamsSchema.parse(request.params);
      const { webhook_test, webhook_only } = TestRuleRequestSchema.parse(request.body);
      
      const rule = store.getRuleById(id);
      if (!rule) {
        return reply.status(404).send({
          success: false,
          error: 'Rule not found',
        });
      }
      
      let matches: any[] = [];
      let webhookTestResult: boolean | null = null;
      
      if (webhook_only) {
        // Only test webhooks, skip SkinBaron API
        request.log.info(`Testing webhooks only for rule ${id}`);
        
        const webhooks = store.getRuleWebhooksForNotification(rule.id!);
        if (webhooks.length > 0) {
          const testResults = await Promise.all(
            webhooks.map(webhook => notificationService.testWebhook(webhook.webhook_url!))
          );
          webhookTestResult = testResults.every(result => result); // All must pass
        }
        
        // Return empty matches array for webhook-only test
        matches = [];
      } else {
        // Normal test: test rule first, then optionally webhooks
        matches = await scheduler.testRule(rule);
        
        if (webhook_test) {
          const webhooks = store.getRuleWebhooksForNotification(rule.id!);
          if (webhooks.length > 0) {
            const testResults = await Promise.all(
              webhooks.map(webhook => notificationService.testWebhook(webhook.webhook_url!))
            );
            webhookTestResult = testResults.every(result => result); // All must pass
          }
        }
      }
      
      request.log.info(`Tested rule ${id}: ${matches.length} matches found`);
      
      return reply.status(200).send({
        success: true,
        data: {
          matches,
          matchCount: matches.length,
          webhookTest: webhookTestResult,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to test rule');
      return reply.status(500).send({
        success: false,
        error: 'Failed to test rule',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
};

export default rulesRoutes;