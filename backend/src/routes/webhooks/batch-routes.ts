import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { BatchWebhookIdsSchema, BatchWebhookDeleteSchema } from '../../database/validation-schemas.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { getAuthUser } from '../../lib/middleware.js';

type RegisterWebhookBatchRoutesOptions = {
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
  if (msg.includes('not found')) throw new AppError(404, msg, 'WEBHOOK_NOT_FOUND');
  if (msg.includes('Access denied')) throw new AppError(403, `You can only ${action} your own webhooks`, 'ACCESS_DENIED');
  throw error;
}

export function registerWebhookBatchRoutes(
  fastify: FastifyInstance,
  { batchRateLimit }: RegisterWebhookBatchRoutesOptions,
): void {
  fastify.post('/batch/enable', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Enable multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          webhook_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 20,
            description: 'Array of webhook IDs to enable. If empty or not provided, enables all webhooks',
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
      const { webhook_ids } = validateWithZod(BatchWebhookIdsSchema, request.body);
      const userId = getAuthUser(request).id;

      let updated = 0;

      if (!webhook_ids || webhook_ids.length === 0) {
        const allWebhooks = await store.webhooks.findByUserId(userId);
        const allIds = allWebhooks.filter(w => !w.is_active).map(w => w.id);
        updated = await store.webhooks.enableBatch(allIds, userId);
      } else {
        try {
          await store.webhooks.validateOwnership(webhook_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'enable');
        }
        updated = await store.webhooks.enableBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully enabled ${updated} webhook(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Enable webhooks');
    }
  });

  fastify.post('/batch/disable', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Disable multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          webhook_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 20,
            description: 'Array of webhook IDs to disable. If empty or not provided, disables all webhooks',
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
      const { webhook_ids } = validateWithZod(BatchWebhookIdsSchema, request.body);
      const userId = getAuthUser(request).id;

      let updated = 0;

      if (!webhook_ids || webhook_ids.length === 0) {
        const allWebhooks = await store.webhooks.findByUserId(userId);
        const allIds = allWebhooks.filter(w => w.is_active).map(w => w.id);
        updated = await store.webhooks.disableBatch(allIds, userId);
      } else {
        try {
          await store.webhooks.validateOwnership(webhook_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'disable');
        }
        updated = await store.webhooks.disableBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully disabled ${updated} webhook(s)`,
        count: updated,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Disable webhooks');
    }
  });

  fastify.post('/batch/delete', {
    config: { rateLimit: batchRateLimit },
    schema: {
      description: 'Delete multiple webhooks or all webhooks for authenticated user',
      tags: ['Webhooks'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          webhook_ids: {
            type: 'array',
            items: { type: 'integer', minimum: 1 },
            maxItems: 20,
            description: 'Array of webhook IDs to delete. If empty, deletes all webhooks (requires confirm_all)',
          },
          confirm_all: {
            type: 'boolean',
            description: 'Must be true to delete all webhooks',
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
      const { webhook_ids, confirm_all } = validateWithZod(BatchWebhookDeleteSchema, request.body);
      const userId = getAuthUser(request).id;

      let deleted = 0;

      if (!webhook_ids || webhook_ids.length === 0) {
        if (!confirm_all) {
          throw new AppError(400, 'Set confirm_all to true to delete all webhooks', 'CONFIRMATION_REQUIRED');
        }

        const allWebhooks = await store.webhooks.findByUserId(userId);
        const allIds = allWebhooks.map(w => w.id);
        deleted = await store.webhooks.deleteBatch(allIds, userId);
      } else {
        try {
          await store.webhooks.validateOwnership(webhook_ids, userId);
        } catch (error: unknown) {
          remapOwnershipValidationError(error, 'delete');
        }
        deleted = await store.webhooks.deleteBatch(webhook_ids, userId);
      }

      return reply.status(200).send({
        success: true,
        message: `Successfully deleted ${deleted} webhook(s)`,
        count: deleted,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Delete webhooks');
    }
  });
}
