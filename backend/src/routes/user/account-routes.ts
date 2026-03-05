import type { FastifyInstance } from 'fastify';
import { registerUserAccountExportRoutes } from './account-export-routes.js';
import { registerUserAccountSessionRoutes } from './account-session-routes.js';
import { registerUserAccountDeleteRoutes } from './account-delete-routes.js';

type RateLimitConfig = {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};

type RegisterUserAccountRoutesOptions = {
  sensitiveOperationRateLimit: RateLimitConfig;
  heavyOperationRateLimit: RateLimitConfig;
};

export function registerUserAccountRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit, heavyOperationRateLimit }: RegisterUserAccountRoutesOptions,
): void {
  registerUserAccountExportRoutes(fastify, { heavyOperationRateLimit });
  registerUserAccountSessionRoutes(fastify, { sensitiveOperationRateLimit });
  registerUserAccountDeleteRoutes(fastify, { sensitiveOperationRateLimit });
}
