import { FastifyRequest, FastifyReply } from 'fastify';
import { ZodError } from 'zod';

/**
 * Custom application error with HTTP status code
 */
export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'AppError';
  }
}

/**
 * Centralized error handler for all routes
 * Handles AppError, ZodError, and generic errors
 */
export function handleError(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
  context: string
): FastifyReply {
  // Log the error
  request.log.error({ error, context }, context);
  
  // Handle custom application errors
  if (error instanceof AppError) {
    return reply.status(error.statusCode).send({
      success: false,
      error: error.message,
      code: error.code,
    });
  }
  
  // Handle Zod validation errors
  if (error instanceof ZodError) {
    const firstIssue = error.issues[0];
    return reply.status(400).send({
      success: false,
      error: firstIssue?.message || 'Validation error',
    });
  }
  
  // Handle generic errors (fallback)
  return reply.status(500).send({
    success: false,
    error: context,
  });
}

/**
 * Common error factory functions
 */
export const Errors = {
  notFound: (resource: string) => 
    new AppError(404, `${resource} not found`, 'NOT_FOUND'),
    
  unauthorized: (message = 'Unauthorized') => 
    new AppError(401, message, 'UNAUTHORIZED'),
    
  forbidden: (message = 'Forbidden') => 
    new AppError(403, message, 'FORBIDDEN'),
    
  badRequest: (message: string) => 
    new AppError(400, message, 'BAD_REQUEST'),
    
  conflict: (message: string) => 
    new AppError(409, message, 'CONFLICT'),
    
  internal: (message = 'Internal server error') => 
    new AppError(500, message, 'INTERNAL_ERROR'),
};
