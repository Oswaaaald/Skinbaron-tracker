import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { MAX_RULES_PER_USER } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { getAuthUser } from '../../lib/middleware.js';
import { CreateRuleRequestSchema, UpdateRuleRequestSchema, RuleParamsSchema } from './shared.js';

type RegisterRuleWriteRoutesOptions = {
  writeRateLimit: {
    max: number;
    timeWindow: string;
    errorResponseBuilder: () => {
      statusCode: number;
      success: boolean;
      error: string;
      message: string;
    };
  };
};

export function registerRuleWriteRoutes(
  fastify: FastifyInstance,
  { writeRateLimit }: RegisterRuleWriteRoutesOptions,
): void {
  fastify.post('/', {
    config: { rateLimit: writeRateLimit },
    schema: {
      description: 'Create a new alert rule for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['search_item'],
        properties: {
          search_item: { type: 'string', minLength: 1, maxLength: 200 },
          min_price: { type: 'number', minimum: 0 },
          max_price: { type: 'number', minimum: 0 },
          min_wear: { type: 'number', minimum: 0, maximum: 1 },
          max_wear: { type: 'number', minimum: 0, maximum: 1 },
          stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          sticker_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          webhook_ids: { type: 'array', items: { type: 'integer', minimum: 1 }, minItems: 0, maxItems: 10 },
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
                sticker_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
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
      const userId = getAuthUser(request).id;
      const userRuleCount = await store.rules.count(userId);
      if (userRuleCount >= MAX_RULES_PER_USER) {
        throw new AppError(400, `You have reached the maximum limit of ${MAX_RULES_PER_USER} rules per user. Please delete some rules before creating new ones.`, 'MAX_RULES_REACHED');
      }

      const bodyData = validateWithZod(CreateRuleRequestSchema, request.body);
      const ruleData = { ...bodyData, user_id: userId };

      if (ruleData.webhook_ids && ruleData.webhook_ids.length > 0) {
        const userWebhooks = await store.webhooks.findByUserId(userId);
        const userWebhookIds = userWebhooks.map(w => w.id);

        const invalidWebhooks = ruleData.webhook_ids.filter((id: number) => !userWebhookIds.includes(id));
        if (invalidWebhooks.length > 0) {
          throw new AppError(400, `Webhook IDs ${invalidWebhooks.join(', ')} do not exist or do not belong to you. Please check that these webhooks haven't been deleted.`, 'INVALID_WEBHOOK_IDS');
        }
      } else {
        ruleData.webhook_ids = [];
      }

      const rule = await store.rules.create(ruleData);
      request.log.info(`Created rule ${rule.id} for user ${rule.user_id}`);

      return reply.status(201).send({
        success: true,
        data: rule,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Create rule');
    }
  });

  fastify.patch('/:id', {
    config: { rateLimit: writeRateLimit },
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
        additionalProperties: false,
        properties: {
          search_item: { type: 'string', minLength: 1, maxLength: 200 },
          min_price: { type: 'number', minimum: 0, nullable: true },
          max_price: { type: 'number', minimum: 0, nullable: true },
          min_wear: { type: 'number', minimum: 0, maximum: 1, nullable: true },
          max_wear: { type: 'number', minimum: 0, maximum: 1, nullable: true },
          stattrak_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          souvenir_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          sticker_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
          webhook_ids: { type: 'array', items: { type: 'integer', minimum: 1 }, minItems: 0, maxItems: 10 },
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
                sticker_filter: { type: 'string', enum: ['all', 'only', 'exclude'] },
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
      const userId = getAuthUser(request).id;
      const { id } = validateWithZod(RuleParamsSchema, request.params);

      const existingRule = await store.rules.findById(id, userId);
      if (!existingRule) {
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }

      const updates = validateWithZod(UpdateRuleRequestSchema, request.body);
      const userWebhooks = await store.webhooks.findByUserId(userId);
      const userWebhookIds = userWebhooks.map(w => w.id);

      if (updates.webhook_ids !== undefined) {
        if (updates.webhook_ids.length > 0) {
          const originalCount = updates.webhook_ids.length;
          const validWebhookIds = updates.webhook_ids.filter((webhookId: number) => userWebhookIds.includes(webhookId));
          updates.webhook_ids = validWebhookIds;
          if (originalCount > validWebhookIds.length) {
            const removedCount = originalCount - validWebhookIds.length;
            request.log.info(`Filtered out ${removedCount} deleted webhook(s) from rule update`);
          }
        }
      }

      const rule = await store.rules.update(id, updates);
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

  fastify.delete('/:id', {
    config: { rateLimit: writeRateLimit },
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
      const userId = getAuthUser(request).id;
      const { id } = validateWithZod(RuleParamsSchema, request.params);

      const existingRule = await store.rules.findById(id, userId);
      if (!existingRule) {
        throw new AppError(404, 'Rule not found', 'RULE_NOT_FOUND');
      }

      const deleted = await store.rules.delete(id, userId);
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
}
