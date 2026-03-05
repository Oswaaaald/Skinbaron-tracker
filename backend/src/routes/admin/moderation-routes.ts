import type { FastifyInstance } from 'fastify';
import { registerAdminRestrictionRoutes } from './moderation-restriction-routes.js';
import { registerAdminSanctionRoutes } from './moderation-sanction-routes.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminModerationRoutes(
  fastify: FastifyInstance,
  options: RegisterAdminRouteOptions,
): void {
  registerAdminRestrictionRoutes(fastify, options);
  registerAdminSanctionRoutes(fastify, options);
}
