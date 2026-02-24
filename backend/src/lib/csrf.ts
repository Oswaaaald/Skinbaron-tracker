import crypto from 'crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import { AppError } from './errors.js';
import { appConfig } from './config.js';

const CSRF_COOKIE = 'sb_csrf';
const CSRF_HEADER = 'x-csrf-token';

/**
 * Generate a cryptographically secure CSRF token
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('base64url');
}

/**
 * Set CSRF token cookie — uses the same domain as auth cookies
 * so both travel together in cross-subdomain deployments.
 *
 * Also clears any stale host-only cookie (no domain attribute) that may
 * linger from before the COOKIE_DOMAIN setting was introduced.  Without
 * this, the browser sends two sb_csrf cookies and the server reads the
 * wrong one, causing "Invalid CSRF token" errors.
 */
export function setCsrfCookie(reply: FastifyReply, token: string, isProduction: boolean): void {
  const cookieOpts = {
    httpOnly: true,
    sameSite: isProduction ? 'none' as const : 'lax' as const,
    secure: isProduction,
    path: '/',
    maxAge: 60 * 60 * 24, // 24 hours
  };

  // Set the canonical cookie (with domain when configured)
  reply.setCookie(CSRF_COOKIE, token, {
    ...cookieOpts,
    domain: appConfig.COOKIE_DOMAIN || undefined,
  });

  // Expire the host-only variant so the browser doesn't send duplicates
  if (appConfig.COOKIE_DOMAIN) {
    reply.setCookie(CSRF_COOKIE, '', {
      ...cookieOpts,
      domain: undefined,
      maxAge: 0,
      expires: new Date(0),
    });
  }
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
  // Note: logout is also skipped - while logout CSRF is theoretically possible,
  // the impact is minimal (forcing logout) vs UX friction of CSRF token issues
  const skipPaths = ['/api/auth/login', '/api/auth/register', '/api/auth/refresh', '/api/auth/logout', '/api/auth/verify-oauth-2fa', '/api/auth/finalize-oauth-registration', '/api/auth/passkey/authenticate-options', '/api/auth/passkey/authenticate-verify'];
  const urlPath = request.url.split('?')[0] ?? ''; // Strip query string for exact match
  if (skipPaths.includes(urlPath)) {
    return;
  }

  // Skip CSRF for Swagger UI requests — Origin/Referer headers are
  // browser-controlled and cannot be forged by JavaScript, so this
  // bypass is safe against cross-origin CSRF attacks.
  const headers = request.headers as Record<string, string | string[] | undefined>;
  const originRaw = headers['origin'];
  const refererRaw = headers['referer'];
  const originStr = Array.isArray(originRaw) ? originRaw[0] ?? '' : (originRaw ?? '');
  const refererStr = Array.isArray(refererRaw) ? refererRaw[0] ?? '' : (refererRaw ?? '');
  const apiBase = appConfig.NEXT_PUBLIC_API_URL;
  if (originStr === apiBase || (refererStr.startsWith(apiBase) && refererStr.includes('/docs'))) {
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
