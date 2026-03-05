import type { FastifyInstance } from 'fastify';
import { registerUserProfileRoutes } from './user/profile-routes.js';
import { registerUserPasswordRoutes } from './user/password-routes.js';
import { registerUserAvatarRoutes } from './user/avatar-routes.js';
import { registerUserAccountRoutes } from './user/account-routes.js';
import { registerUserSecurityRoutes } from './user/security-routes.js';
import { userSensitiveRateLimit, userAvatarRateLimit, userHeavyRateLimit } from '../lib/rate-limit.js';

/**
 * User profile routes - Authenticated users can manage their own profile
 */
export default async function userRoutes(fastify: FastifyInstance) {
  // Local hook for defense in depth - ensures all routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);

  const sensitiveOperationRateLimit = userSensitiveRateLimit;
  const avatarRateLimit = userAvatarRateLimit;
  const heavyOperationRateLimit = userHeavyRateLimit;

  registerUserProfileRoutes(fastify, { sensitiveOperationRateLimit });
  registerUserPasswordRoutes(fastify, { sensitiveOperationRateLimit });
  registerUserAvatarRoutes(fastify, { avatarRateLimit });
  registerUserAccountRoutes(fastify, {
    sensitiveOperationRateLimit,
    heavyOperationRateLimit,
  });
  registerUserSecurityRoutes(fastify, { sensitiveOperationRateLimit });
}
