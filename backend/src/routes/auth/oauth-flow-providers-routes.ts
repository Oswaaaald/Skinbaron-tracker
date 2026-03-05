import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { ACCESS_COOKIE, baseCookieOptions } from '../../lib/middleware.js';
import { AppError } from '../../lib/errors.js';
import {
  getEnabledProviders,
  isProviderEnabled,
  createAuthorizationUrl,
  encryptOAuthState,
  OAUTH_STATE_COOKIE,
} from '../../lib/oauth.js';
import {
  OAuthProviderParamsSchema,
  OAuthProviderQuerySchema,
} from '../../database/schemas.js';
import { validateWithZod } from '../../lib/validation-handler.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthProviderFlowRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig }: AuthRoutesContext,
): void {
  fastify.get('/oauth/providers', {
    schema: {
      description: 'Get list of enabled OAuth providers',
      tags: ['Authentication'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                providers: { type: 'array', items: { type: 'string' } },
              },
            },
          },
        },
      },
    },
  }, async (_request, reply) => {
    return reply.send({
      success: true,
      data: { providers: getEnabledProviders() },
    });
  });

  fastify.get<{ Params: { provider: string }; Querystring: { mode?: string } }>('/oauth/:provider', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Initiate OAuth flow — redirects to provider authorization page',
      tags: ['Authentication'],
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
      querystring: {
        type: 'object',
        properties: { mode: { type: 'string', enum: ['login', 'register'] } },
      },
    },
  }, async (request, reply) => {
    const { provider } = validateWithZod(OAuthProviderParamsSchema, request.params);
    const { mode } = validateWithZod(OAuthProviderQuerySchema, request.query);

    if (!isProviderEnabled(provider)) {
      throw new AppError(400, `OAuth provider "${provider}" is not available`, 'INVALID_PROVIDER');
    }

    let linkUserId: number | undefined;
    try {
      const token = request.cookies?.[ACCESS_COOKIE] || AuthService.extractTokenFromHeader(request.headers.authorization ?? '');
      if (token) {
        const payload = AuthService.verifyToken(token, 'access');
        if (payload?.userId) linkUserId = payload.userId;
      }
    } catch {
      // not logged in — normal login flow
    }

    const { url, state, codeVerifier } = createAuthorizationUrl(provider);

    reply.setCookie(OAUTH_STATE_COOKIE, encryptOAuthState(state, codeVerifier, linkUserId, mode), {
      ...baseCookieOptions(),
      maxAge: 600,
    });

    return reply.redirect(url.toString());
  });
}
