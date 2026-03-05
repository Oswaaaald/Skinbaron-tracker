import type { FastifyInstance } from 'fastify';
import { registerUserProfileRoutes } from './user/profile-routes.js';
import { registerUserPasswordRoutes } from './user/password-routes.js';
import { registerUserAvatarRoutes } from './user/avatar-routes.js';
import { registerUserAccountRoutes } from './user/account-routes.js';
import { registerUserSecurityRoutes } from './user/security-routes.js';

/**
 * User profile routes - Authenticated users can manage their own profile
 */
export default async function userRoutes(fastify: FastifyInstance) {
  // Local hook for defense in depth - ensures all routes require authentication
  fastify.addHook('preHandler', fastify.authenticate);

  // Rate limiting for sensitive operations
  const sensitiveOperationRateLimit = {
    max: 5,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many attempts. Please try again in 1 minute.',
    }),
  };

  // Strict rate limit for avatar operations (file I/O + image processing)
  const avatarRateLimit = {
    max: 3,
    timeWindow: '5 minutes',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many avatar changes. Please try again in 5 minutes.',
    }),
  };

  // Stricter rate limit for expensive/destructive operations
  const heavyOperationRateLimit = {
    max: 3,
    timeWindow: '5 minutes',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many requests. Please try again later.',
    }),
  };

  registerUserProfileRoutes(fastify, { sensitiveOperationRateLimit });
  registerUserPasswordRoutes(fastify, { sensitiveOperationRateLimit });
  registerUserAvatarRoutes(fastify, { avatarRateLimit });
  registerUserAccountRoutes(fastify, {
    sensitiveOperationRateLimit,
    heavyOperationRateLimit,
  });
  registerUserSecurityRoutes(fastify, { sensitiveOperationRateLimit });
}
