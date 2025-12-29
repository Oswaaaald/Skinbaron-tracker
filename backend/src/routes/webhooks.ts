import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getStore, CreateUserWebhookSchema } from '../lib/store.js';

// Query parameters schemas
const WebhookParamsSchema = z.object({
  id: z.string().transform(val => parseInt(val, 10)),
});

const WebhookQuerySchema = z.object({
  decrypt: z.string().default('false').transform(val => val === 'true'),
});

// Route handlers
const webhooksRoutes: FastifyPluginAsync = async (fastify) => {
  const store = getStore();

  /**
   * POST /webhooks - Create a new webhook for the authenticated user
   */
  fastify.post('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Create a new webhook for the authenticated user',
      tags: ['Webhooks'],
      body: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 50 },
          webhook_url: { type: 'string', format: 'uri' },
          webhook_type: { type: 'string', enum: ['discord', 'slack', 'teams', 'generic'] },
          is_active: { type: 'boolean' },
        },
        required: ['name', 'webhook_url'],
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
                name: { type: 'string' },
                webhook_type: { type: 'string' },
                is_active: { type: 'boolean' },
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
      const webhookData = CreateUserWebhookSchema.parse(request.body);
      const webhook = store.createUserWebhook(request.user!.id, webhookData);
      
      // Don't return encrypted URL in response
      const { webhook_url_encrypted, ...safeWebhook } = webhook;
      
      return reply.status(201).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to create webhook');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to create webhook',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /webhooks - Get all webhooks for the authenticated user
   */
  fastify.get('/', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get all webhooks for the authenticated user',
      tags: ['Webhooks'],
      querystring: {
        type: 'object',
        properties: {
          decrypt: { type: 'string', enum: ['true', 'false'], default: 'false' },
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
                  user_id: { type: 'number' },
                  name: { type: 'string' },
                  webhook_url: { type: 'string' },
                  webhook_type: { type: 'string' },
                  is_active: { type: 'boolean' },
                  created_at: { type: 'string' },
                  updated_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const { decrypt } = WebhookQuerySchema.parse(request.query);
      const webhooks = store.getUserWebhooksByUserId(request.user!.id, decrypt);
      
      // Remove encrypted field from response
      const safeWebhooks = webhooks.map(webhook => {
        const { webhook_url_encrypted, ...safe } = webhook;
        return safe;
      });
      
      return reply.status(200).send({
        success: true,
        data: safeWebhooks,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get webhooks');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve webhooks',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /webhooks/:id - Get a specific webhook for the authenticated user
   */
  fastify.get('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get a specific webhook for the authenticated user',
      tags: ['Webhooks'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      querystring: {
        type: 'object',
        properties: {
          decrypt: { type: 'string', enum: ['true', 'false'], default: 'false' },
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
                name: { type: 'string' },
                webhook_url: { type: 'string' },
                webhook_type: { type: 'string' },
                is_active: { type: 'boolean' },
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
      const { id } = WebhookParamsSchema.parse(request.params);
      const { decrypt } = WebhookQuerySchema.parse(request.query);
      const webhook = store.getUserWebhookById(id, decrypt);
      
      if (!webhook || webhook.user_id !== request.user!.id) {
        return reply.status(404).send({
          success: false,
          error: 'Webhook not found',
        });
      }
      
      // Remove encrypted field from response
      const { webhook_url_encrypted, ...safeWebhook } = webhook;
      
      return reply.status(200).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get webhook');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve webhook',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * PUT /webhooks/:id - Update a webhook for the authenticated user
   */
  fastify.put('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Update a webhook for the authenticated user',
      tags: ['Webhooks'],
      params: {
        type: 'object',
        properties: {
          id: { type: 'string' },
        },
      },
      body: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 50 },
          webhook_url: { type: 'string', format: 'uri' },
          webhook_type: { type: 'string', enum: ['discord', 'slack', 'teams', 'generic'] },
          is_active: { type: 'boolean' },
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
                name: { type: 'string' },
                webhook_type: { type: 'string' },
                is_active: { type: 'boolean' },
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
      const { id } = WebhookParamsSchema.parse(request.params);
      const updates = CreateUserWebhookSchema.partial().parse(request.body);
      
      const webhook = store.updateUserWebhook(id, request.user!.id, updates);
      
      // Remove encrypted field from response
      const { webhook_url_encrypted, ...safeWebhook } = webhook;
      
      return reply.status(200).send({
        success: true,
        data: safeWebhook,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to update webhook');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      if (error instanceof Error && error.message.includes('not found')) {
        return reply.status(404).send({
          success: false,
          error: 'Webhook not found',
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to update webhook',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * DELETE /webhooks/:id - Delete a webhook for the authenticated user
   */
  fastify.delete('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Delete a webhook for the authenticated user',
      tags: ['Webhooks'],
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
      const { id } = WebhookParamsSchema.parse(request.params);
      const deleted = store.deleteUserWebhook(id, request.user!.id);
      
      if (!deleted) {
        return reply.status(404).send({
          success: false,
          error: 'Webhook not found',
        });
      }
      
      return reply.status(200).send({
        success: true,
        message: 'Webhook deleted successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to delete webhook');
      
      if (error instanceof z.ZodError) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          details: error.issues,
        });
      }
      
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete webhook',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  /**
   * GET /webhooks/active - Get all active webhooks for the authenticated user (with decrypted URLs)
   */
  fastify.get('/active', {
    preHandler: [fastify.authenticate],
    schema: {
      description: 'Get all active webhooks for the authenticated user with decrypted URLs',
      tags: ['Webhooks'],
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
                  name: { type: 'string' },
                  webhook_url: { type: 'string' },
                  webhook_type: { type: 'string' },
                  is_active: { type: 'boolean' },
                  created_at: { type: 'string' },
                  updated_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const webhooks = store.getUserActiveWebhooks(request.user!.id);
      
      // Remove encrypted field from response
      const safeWebhooks = webhooks.map(webhook => {
        const { webhook_url_encrypted, ...safe } = webhook;
        return safe;
      });
      
      return reply.status(200).send({
        success: true,
        data: safeWebhooks,
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get active webhooks');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve active webhooks',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
};

export default webhooksRoutes;