import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { store } from '../database/index.js';
import { RuleSchema } from '../database/schemas.js';
import { MAX_RULES_PER_USER } from '../lib/config.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';

// Extend FastifyInstance type for authenticate
declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
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

// Use partial schema for updates to allow partial modifications
const UpdateRuleRequestSchema = CreateRuleRequestSchema.partial();

const RuleParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

// Route handlers
const rulesRoutes: FastifyPluginAsync = async (fastify) => {

  /**
   * GET /rules - Get all rules for authenticated user
   */
  fastify.get('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get all alert rules for authenticated user',
      tags: ['Rules'],
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
                  user_id: { type: 'number' },
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
      return handleRouteError(error, request, reply, 'Get rules');
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
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
                user_id: { type: 'number' },
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
      // Check max rules limit
      const userRules = store.getRulesByUserId(request.user!.id);
      if (userRules.length >= MAX_RULES_PER_USER) {
        throw new AppError(400, `You have reached the maximum limit of ${MAX_RULES_PER_USER} rules per user. Please delete some rules before creating new ones.`, 'MAX_RULES_REACHED');
      }
      
      // Parse body but add user_id from authenticated user
      const bodyData = request.body as Record<string, unknown>;
      
      const ruleData = validateWithZod(CreateRuleRequestSchema, {
        ...bodyData,
        user_id: request.user!.id,
      }, 'Create rule');
      
      // Validate webhook_ids if provided - must belong to user
      if (ruleData.webhook_ids && ruleData.webhook_ids.length > 0) {
        const userWebhooks = store.getUserWebhooksByUserId(request.user!.id);
        const userWebhookIds = userWebhooks.map(w => w.id);
        
        const invalidWebhooks = ruleData.webhook_ids.filter((id: number) => !userWebhookIds.includes(id));
        if (invalidWebhooks.length > 0) {
          throw new AppError(400, `Webhook IDs ${invalidWebhooks.join(', ')} do not exist or do not belong to you. Please check that these webhooks haven't been deleted.`, 'INVALID_WEBHOOK_IDS');
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
      return handleRouteError(error, request, reply, 'Create rule');
    }
  });

  /**
   * PUT /rules/:id - Update a rule
   */
  fastify.patch('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Update an existing rule (user-owned, partial update)',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
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
                user_id: { type: 'number' },
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
      const { id } = validateWithZod(RuleParamsSchema, request.params, 'Rule params');
      
      // Check if rule exists and user owns it
      const existingRule = store.getRuleById(id);
      if (!existingRule) {
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }

      if (existingRule.user_id !== request.user!.id) {
        throw new AppError(403, 'You can only update your own rules', 'ACCESS_DENIED');
      }

      // Parse body but add user_id from authenticated user (same as create)
      const bodyData = request.body as Record<string, unknown>;
      
      const updates = validateWithZod(UpdateRuleRequestSchema, {
        ...bodyData,
        user_id: request.user!.id,
      }, 'Update rule');
      
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
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }
      
      request.log.info(`Updated rule ${rule.id}`);
      
      return reply.status(200).send({
        success: true,
        data: rule,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Update rule');
    }
  });

  /**
   * DELETE /rules/:id - Delete a rule
   */
  fastify.delete('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Delete a rule (user-owned)',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
      const { id } = validateWithZod(RuleParamsSchema, request.params, 'Rule params');
      
      // Check if rule exists and user owns it
      const existingRule = store.getRuleById(id);
      if (!existingRule) {
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }

      if (existingRule.user_id !== request.user!.id) {
        throw new AppError(403, 'You can only delete your own rules', 'ACCESS_DENIED');
      }

      const deleted = store.deleteRule(id);
      
      if (!deleted) {
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }
      
      request.log.info(`Deleted rule ${id}`);
      
      return reply.status(200).send({
        success: true,
        message: 'Rule deleted successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete rule');
    }
  });

  /**
   * POST /rules/batch/enable - Enable multiple or all rules
   */
  fastify.post('/batch/enable', {
    schema: {
      description: 'Enable multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          rule_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of rule IDs to enable. If empty or not provided, enables all rules'
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { rule_ids } = request.body as { rule_ids?: number[] };
      const userId = request.user!.id;

      let updated = 0;
      
      if (!rule_ids || rule_ids.length === 0) {
        // Enable all rules for this user
        const allRules = store.getRulesByUserId(userId);
        const allIds = allRules.filter(r => !r.enabled).map(r => r.id!);
        updated = store.enableRulesBatch(allIds, userId);
      } else {
        // Validate ownership of all rules
        for (const ruleId of rule_ids) {
          const rule = store.getRuleById(ruleId);
          if (!rule) {
            throw new AppError(404, `Rule ${ruleId} not found`, 'RULE_NOT_FOUND');
          }
          if (rule.user_id !== userId) {
            throw new AppError(403, 'You can only enable your own rules', 'ACCESS_DENIED');
          }
        }
        // Enable specific rules (optimized batch operation)
        updated = store.enableRulesBatch(rule_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully enabled ${updated} rule(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Enable rules');
    }
  });

  /**
   * POST /rules/batch/disable - Disable multiple or all rules
   */
  fastify.post('/batch/disable', {
    schema: {
      description: 'Disable multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          rule_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of rule IDs to disable. If empty or not provided, disables all rules'
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { rule_ids } = request.body as { rule_ids?: number[] };
      const userId = request.user!.id;

      let updated = 0;
      
      if (!rule_ids || rule_ids.length === 0) {
        // Disable all rules for this user
        const allRules = store.getRulesByUserId(userId);
        const allIds = allRules.filter(r => r.enabled).map(r => r.id!);
        updated = store.disableRulesBatch(allIds, userId);
      } else {
        // Validate ownership of all rules
        for (const ruleId of rule_ids) {
          const rule = store.getRuleById(ruleId);
          if (!rule) {
            throw new AppError(404, `Rule ${ruleId} not found`, 'RULE_NOT_FOUND');
          }
          if (rule.user_id !== userId) {
            throw new AppError(403, 'You can only disable your own rules', 'ACCESS_DENIED');
          }
        }
        // Disable specific rules (optimized batch operation)
        updated = store.disableRulesBatch(rule_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully disabled ${updated} rule(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Disable rules');
    }
  });

  /**
   * POST /rules/batch/delete - Delete multiple or all rules
   */
  fastify.post('/batch/delete', {
    schema: {
      description: 'Delete multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        properties: {
          rule_ids: { 
            type: 'array', 
            items: { type: 'number' },
            description: 'Array of rule IDs to delete. If empty or not provided, deletes all rules'
          },
          confirm_all: {
            type: 'boolean',
            description: 'Required confirmation when deleting all rules',
          },
        },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            count: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { rule_ids, confirm_all } = request.body as { rule_ids?: number[]; confirm_all?: boolean };
      const userId = request.user!.id;

      let deleted = 0;
      
      if (!rule_ids || rule_ids.length === 0) {
        // Delete all rules - require confirmation
        if (!confirm_all) {
          throw new AppError(400, 'Set confirm_all: true to delete all rules', 'CONFIRMATION_REQUIRED');
        }

        const allRules = store.getRulesByUserId(userId);
        const allIds = allRules.map(r => r.id!);
        deleted = store.deleteRulesBatch(allIds, userId);
      } else {
        // Validate ownership of all rules
        for (const ruleId of rule_ids) {
          const rule = store.getRuleById(ruleId);
          if (!rule) {
            throw new AppError(404, `Rule ${ruleId} not found`, 'RULE_NOT_FOUND');
          }
          if (rule.user_id !== userId) {
            throw new AppError(403, 'You can only delete your own rules', 'ACCESS_DENIED');
          }
        }
        // Delete specific rules (optimized batch operation)
        deleted = store.deleteRulesBatch(rule_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully deleted ${deleted} rule(s)`,
        count: deleted,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete rules');
    }
  });
};

export default rulesRoutes;