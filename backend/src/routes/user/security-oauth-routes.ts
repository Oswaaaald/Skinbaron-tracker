import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getClientIp, getAuthUser } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { OAuthUnlinkParamsSchema } from '../../database/schemas.js';
import type { RegisterUserSecurityRoutesOptions } from './security-types.js';

export function registerUserSecurityOAuthRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserSecurityRoutesOptions,
): void {
  fastify.get('/oauth-accounts', {
    schema: {
      description: 'Get linked OAuth accounts',
      tags: ['User'],
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
                  provider: { type: 'string' },
                  provider_email: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const accounts = await store.oauth.findByUserId(userId);
      return reply.status(200).send({ success: true, data: accounts });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get OAuth accounts');
    }
  });

  fastify.delete<{ Params: { provider: string } }>('/oauth-accounts/:provider', {
    config: { rateLimit: sensitiveOperationRateLimit },
    schema: {
      description: 'Unlink an OAuth provider',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const user = getAuthUser(request);
      const { provider } = validateWithZod(OAuthUnlinkParamsSchema, request.params);
      const accounts = await store.oauth.findByUserId(user.id);

      const target = accounts.find((a) => a.provider === provider);
      if (!target) {
        throw new AppError(404, 'This OAuth provider is not linked to your account', 'OAUTH_NOT_LINKED');
      }

      const fullUser = await store.users.findById(user.id);
      const hasPassword = !!fullUser?.password_hash;
      if (!hasPassword && accounts.length <= 1) {
        throw new AppError(
          400,
          'Cannot unlink your only login method. Set a password first.',
          'LAST_LOGIN_METHOD',
        );
      }

      await store.oauth.unlink(user.id, provider);

      await store.audit.createLog(
        user.id,
        'oauth_unlinked',
        JSON.stringify({ provider }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({ success: true, message: `${provider} account unlinked` });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Unlink OAuth account');
    }
  });
}
