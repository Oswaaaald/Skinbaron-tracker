import type { FastifyInstance } from 'fastify';
import { registerAdminOperationalCoreRoutes } from './operations-core-routes.js';
import { registerAdminOperationalPendingUserRoutes } from './operations-pending-user-routes.js';
import { registerAdminOperationalLogRoutes } from './operations-log-routes.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminOperationalRoutes(
  fastify: FastifyInstance,
  options: RegisterAdminRouteOptions,
): void {
  registerAdminOperationalCoreRoutes(fastify, options);
  registerAdminOperationalPendingUserRoutes(fastify, options);
  registerAdminOperationalLogRoutes(fastify);
}
