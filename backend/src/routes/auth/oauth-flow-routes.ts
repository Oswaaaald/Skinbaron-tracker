import type { FastifyInstance } from 'fastify';
import { registerOAuthProviderFlowRoutes } from './oauth-flow-providers-routes.js';
import { registerOAuthCallbackRoutes } from './oauth-flow-callback-routes.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthFlowRoutes(
  fastify: FastifyInstance,
  context: AuthRoutesContext,
): void {
  registerOAuthProviderFlowRoutes(fastify, context);
  registerOAuthCallbackRoutes(fastify, context);
}
