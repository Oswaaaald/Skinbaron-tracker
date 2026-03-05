import type { FastifyInstance } from 'fastify';
import { registerUserTwoFactorRoutes } from './security-2fa-routes.js';
import { registerUserPasskeyRoutes } from './security-passkey-routes.js';
import { registerUserSecurityAuditRoutes } from './security-audit-routes.js';
import { registerUserSecurityOAuthRoutes } from './security-oauth-routes.js';
import type { RegisterUserSecurityRoutesOptions } from './security-types.js';

export function registerUserSecurityRoutes(
  fastify: FastifyInstance,
  options: RegisterUserSecurityRoutesOptions,
): void {
  registerUserTwoFactorRoutes(fastify, options);
  registerUserPasskeyRoutes(fastify, options);
  registerUserSecurityAuditRoutes(fastify);
  registerUserSecurityOAuthRoutes(fastify, options);
}
