import { FastifyInstance, FastifyReply } from 'fastify';
import { ACCESS_COOKIE, REFRESH_COOKIE, baseCookieOptions } from '../lib/middleware.js';
import { registerPasswordAuthRoutes } from './auth/password-routes.js';
import { registerSessionAuthRoutes } from './auth/session-routes.js';
import { registerOAuthFlowRoutes } from './auth/oauth-flow-routes.js';
import { registerOAuthAccountRoutes } from './auth/oauth-account-routes.js';
import { registerPasskeyAuthRoutes } from './auth/passkey-routes.js';
import type { AuthRoutesContext } from './auth/shared.js';
import { authStrictRateLimit } from '../lib/rate-limit.js';

/**
 * Authentication routes
 */
export default async function authRoutes(fastify: FastifyInstance) {
  const authRateLimitConfig = authStrictRateLimit;

  const setAuthCookies = (
    reply: FastifyReply,
    accessToken: { token: string; expiresAt: number },
    refreshToken: { token: string; expiresAt: number },
  ) => {
    reply.setCookie(ACCESS_COOKIE, accessToken.token, baseCookieOptions(accessToken.expiresAt));
    reply.setCookie(REFRESH_COOKIE, refreshToken.token, baseCookieOptions(refreshToken.expiresAt));
  };

  const context: AuthRoutesContext = {
    authRateLimitConfig,
    setAuthCookies,
  };

  registerPasswordAuthRoutes(fastify, context);
  registerSessionAuthRoutes(fastify, context);
  registerOAuthFlowRoutes(fastify, context);
  registerOAuthAccountRoutes(fastify, context);
  registerPasskeyAuthRoutes(fastify, context);
}
