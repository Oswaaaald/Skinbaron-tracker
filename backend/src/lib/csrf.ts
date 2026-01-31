import crypto from 'crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import { AppError } from './errors.js';

const CSRF_COOKIE = 'sb_csrf';
const CSRF_HEADER = 'x-csrf-token';

/**
 * Generate a cryptographically secure CSRF token
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Set CSRF token cookie
 */
export function setCsrfCookie(reply: FastifyReply, token: string, isProduction: boolean): void {
  reply.setCookie(CSRF_COOKIE, token, {
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    secure: isProduction,
    path: '/',
    maxAge: 60 * 60 * 24, // 24 hours
  });
}

/**
 * CSRF Protection Middleware for mutating requests (POST, PUT, PATCH, DELETE)
 * Uses double-submit cookie pattern
 */
export async function csrfProtection(request: FastifyRequest): Promise<void> {
  const method = request.method;
  
  // Only protect mutating requests
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return;
  }

  // Skip CSRF for auth routes (they have their own protection via rate-limiting)
  // and for public endpoints
  const skipPaths = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/api/auth/logout'];
  if (skipPaths.some(path => request.url.startsWith(path))) {
    return;
  }

  const tokenFromCookie = request.cookies[CSRF_COOKIE];
  let tokenFromHeader = request.headers[CSRF_HEADER];
  
  // Handle array headers (Fastify can return string[])
  if (Array.isArray(tokenFromHeader)) {
    tokenFromHeader = tokenFromHeader[0];
  }

  // Both must exist and match (double-submit pattern)
  if (!tokenFromCookie || !tokenFromHeader) {
    throw new AppError(403, 'CSRF token missing', 'CSRF_TOKEN_MISSING');
  }

  // Use constant-time comparison to prevent timing attacks
  try {
    const bufferCookie = Buffer.from(tokenFromCookie, 'utf8');
    const bufferHeader = Buffer.from(tokenFromHeader, 'utf8');
    
    if (bufferCookie.length !== bufferHeader.length || !crypto.timingSafeEqual(bufferCookie, bufferHeader)) {
      throw new AppError(403, 'Invalid CSRF token', 'CSRF_TOKEN_INVALID');
    }
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(403, 'Invalid CSRF token', 'CSRF_TOKEN_INVALID');
  }
}

/**
 * Endpoint to get a new CSRF token (for initial page loads)
 */
export function getCsrfToken(): string {
  return generateCsrfToken();
}
