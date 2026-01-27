import { FastifyRequest, FastifyReply } from 'fastify';
import { ZodError, ZodSchema } from 'zod';
import { AppError } from './errors.js';

/**
 * Unified Zod validation wrapper
 * Validates data with Zod schema and returns typed result
 * Throws AppError on validation failure with user-friendly message
 */
export function validateWithZod<T>(
  schema: ZodSchema<T>,
  data: unknown,
  _context: string = 'Input'
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
  // Log error for debugging
  request.log.error({ error, context }, `Error in ${context}`);
  
  // Handle AppError (custom errors with status codes)
  if (error instanceof AppError) {
    return reply.status(error.statusCode).send({
      success: false,
      error: error.message,
      ...(error.code && { code: error.code }),
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
  
  // Handle generic Error instances
  if (error instanceof Error) {
    // Don't expose internal error messages in production
    const isProduction = process.env['NODE_ENV'] === 'production';
    return reply.status(500).send({
      success: false,
      error: isProduction ? 'Internal server error' : error.message,
    });
  }
  
  // Fallback for unknown error types
  return reply.status(500).send({
    success: false,
    error: 'An unexpected error occurred',
  });
}

/**
 * Optional: Safe parse wrapper for non-throwing validation
 * Returns validation result without throwing
 */
export function safeValidateWithZod<T>(
  schema: ZodSchema<T>,
  data: unknown
): { success: true; data: T } | { success: false; error: string } {
  const result = schema.safeParse(data);
  
  if (result.success) {
    return { success: true, data: result.data };
  }
  
  const firstIssue = result.error.issues[0];
  return {
    success: false,
    error: firstIssue?.message || 'Validation failed',
  };
}
