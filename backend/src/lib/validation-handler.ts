import { FastifyRequest, FastifyReply } from 'fastify';
import { ZodError, ZodSchema } from 'zod';
import { AppError } from './errors.js';
import { captureException } from './sentry.js';

/**
 * Unified Zod validation wrapper
 * Validates data with Zod schema and returns typed result
 * Throws AppError on validation failure with user-friendly message
 */
export function validateWithZod<T>(
  schema: ZodSchema<T>,
  data: unknown
): T {
  try {
    return schema.parse(data);
  } catch (error) {
    if (error instanceof ZodError) {
      // Get first error message (most user-friendly)
      const firstIssue = error.issues[0];
      const message = firstIssue?.message || 'Validation failed';
      
      // Throw AppError which will be caught by route handler
      throw new AppError(400, message, 'VALIDATION_ERROR');
    }
    throw error;
  }
}

/**
 * Centralized error response handler
 * Use this in all route catch blocks for consistent error handling
 */
export function handleRouteError(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
  context: string
): FastifyReply {
  // Log error for debugging — use 'err' key so pino serializes message + stack
  request.log.error({ err: error, context }, `Error in ${context}`);
  
  // Handle AppError (custom errors with status codes)
  if (error instanceof AppError) {
    return reply.status(error.statusCode).send({
      success: false,
      error: error.message,
      ...(error.code && { code: error.code }),
      ...(error.data && { data: error.data }),
    });
  }
  
  // Handle ZodError (should be caught by validateWithZod, but just in case)
  if (error instanceof ZodError) {
    const firstIssue = error.issues[0];
    return reply.status(400).send({
      success: false,
      error: firstIssue?.message || 'Validation error',
    });
  }
  
  // Handle generic Error instances (unexpected 500s → report to Sentry)
  if (error instanceof Error) {
    captureException(error, { context, url: request.url, method: request.method });
    const isProduction = process.env['NODE_ENV'] === 'production';
    return reply.status(500).send({
      success: false,
      error: isProduction ? 'Internal server error' : error.message,
    });
  }
  
  // Fallback for unknown error types
  captureException(error, { context, url: request.url, method: request.method });
  return reply.status(500).send({
    success: false,
    error: 'An unexpected error occurred',
  });
}
