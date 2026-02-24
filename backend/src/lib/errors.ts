/**
 * Custom application error with HTTP status code
 */
export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string,
    public data?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AppError';
  }
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
