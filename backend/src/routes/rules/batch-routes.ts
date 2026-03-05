import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { BatchRuleIdsSchema, BatchRuleDeleteSchema } from '../../database/validation-schemas.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { getAuthUser } from '../../lib/middleware.js';

type RegisterRuleBatchRoutesOptions = {
  batchRateLimit: {
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

function remapOwnershipValidationError(error: unknown, action: 'enable' | 'disable' | 'delete'): never {
  const msg = error instanceof Error ? error.message : '';
  if (msg.includes('not found')) throw new AppError(404, msg, 'RULE_NOT_FOUND');
  if (msg.includes('Access denied')) throw new AppError(403, `You can only ${action} your own rules`, 'ACCESS_DENIED');
  throw error;
}

export function registerRuleBatchRoutes(
  fastify: FastifyInstance,
  { batchRateLimit }: RegisterRuleBatchRoutesOptions,
): void {
  fastify.post('/batch/enable', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Enable multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rule_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 50,
            description: 'Array of rule IDs to enable. If empty or not provided, enables all rules',
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
      const { rule_ids } = validateWithZod(BatchRuleIdsSchema, request.body);
      const userId = getAuthUser(request).id;

      let updated = 0;

      if (!rule_ids || rule_ids.length === 0) {
        const allRules = await store.rules.findByUserId(userId);
        const allIds = allRules
          .filter(r => !r.enabled && r.id !== undefined)
          .map(r => r.id);
        updated = await store.rules.enableBatch(allIds, userId);
      } else {
        try {
          await store.rules.validateOwnership(rule_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'enable');
        }
        updated = await store.rules.enableBatch(rule_ids, userId);
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

  fastify.post('/batch/disable', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Disable multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rule_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 50,
            description: 'Array of rule IDs to disable. If empty or not provided, disables all rules',
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
      const { rule_ids } = validateWithZod(BatchRuleIdsSchema, request.body);
      const userId = getAuthUser(request).id;

      let updated = 0;

      if (!rule_ids || rule_ids.length === 0) {
        const allRules = await store.rules.findByUserId(userId);
        const allIds = allRules
          .filter(r => r.enabled && r.id !== undefined)
          .map(r => r.id);
        updated = await store.rules.disableBatch(allIds, userId);
      } else {
        try {
          await store.rules.validateOwnership(rule_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'disable');
        }
        updated = await store.rules.disableBatch(rule_ids, userId);
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

  fastify.post('/batch/delete', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Delete multiple rules or all rules for authenticated user',
      tags: ['Rules'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          rule_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 50,
            description: 'Array of rule IDs to delete. If empty or not provided, deletes all rules',
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
      const { rule_ids, confirm_all } = validateWithZod(BatchRuleDeleteSchema, request.body);
      const userId = getAuthUser(request).id;

      let deleted = 0;

      if (!rule_ids || rule_ids.length === 0) {
        if (!confirm_all) {
          throw new AppError(400, 'Set confirm_all: true to delete all rules', 'CONFIRMATION_REQUIRED');
        }

        const allRules = await store.rules.findByUserId(userId);
        const allIds = allRules
          .filter((r): r is typeof r & { id: number } => r.id !== undefined)
          .map(r => r.id);
        deleted = await store.rules.deleteBatch(allIds, userId);
      } else {
        try {
          await store.rules.validateOwnership(rule_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'delete');
        }
        deleted = await store.rules.deleteBatch(rule_ids, userId);
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
}
