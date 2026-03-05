import type { FastifyInstance } from 'fastify';
import { registerAdminUserOverviewRoutes } from './admin/user-overview-routes.js';
import { registerAdminUserAvatarRoutes } from './admin/user-avatar-routes.js';
import { registerAdminUserLifecycleRoutes } from './admin/user-lifecycle-routes.js';
import { registerAdminUserPrivilegeRoutes } from './admin/user-privilege-routes.js';
import { registerAdminModerationRoutes } from './admin/moderation-routes.js';
import { registerAdminOperationalRoutes } from './admin/operations-routes.js';
import { adminWriteRateLimit } from '../lib/rate-limit.js';

/**
 * Admin routes - All routes require admin privileges
 */
export default async function adminRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);
  fastify.addHook('preHandler', fastify.requireAdmin);


  registerAdminUserOverviewRoutes(fastify);
  registerAdminUserAvatarRoutes(fastify, { adminWriteRateLimit });
  registerAdminUserLifecycleRoutes(fastify, { adminWriteRateLimit });
  registerAdminUserPrivilegeRoutes(fastify, { adminWriteRateLimit });

  registerAdminModerationRoutes(fastify, { adminWriteRateLimit });
  registerAdminOperationalRoutes(fastify, { adminWriteRateLimit });
}
