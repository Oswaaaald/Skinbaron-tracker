import type { FastifyInstance } from 'fastify';
import { registerOAuthPendingRegistrationRoutes } from './oauth-account-pending-registration-routes.js';
import { registerOAuthTwoFactorRoutes } from './oauth-account-2fa-routes.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthAccountRoutes(
  fastify: FastifyInstance,
  context: AuthRoutesContext,
): void {
  registerOAuthPendingRegistrationRoutes(fastify, context);
  registerOAuthTwoFactorRoutes(fastify, context);
}
