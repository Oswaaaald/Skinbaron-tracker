import { FastifyRequest, FastifyReply } from 'fastify';
import '@fastify/cookie';
import { LRUCache } from 'lru-cache';
import { AuthService } from './auth.js';
import { store } from '../database/index.js';
import type { User } from '../database/schemas.js';
import { AppError } from './errors.js';
import { appConfig } from './config.js';

/**
 * Modern LRU cache for user data (2026 best practices)
 * - Automatic TTL expiration
 * - Memory-efficient with max size limit
 * - O(1) access time
 */
const userCache = new LRUCache<number, User>({
  max: 500, // Increased from 200 for better performance
  ttl: 30_000, // 30 seconds TTL
  updateAgeOnGet: true, // Reset TTL on access
  allowStale: false,
});

/**
 * Invalidate user cache entry (called after user updates/deletion)
 */
export function invalidateUserCache(userId: number): void {
  userCache.delete(userId);
}

/**
 * Get user from cache or database
 */
async function getUserById(id: number): Promise<User | null> {
  const cached = userCache.get(id);
  if (cached) return cached;

  const user = await store.getUserById(id);

  if (user) {
    userCache.set(id, user);
  }

  return user;
}

/**
 * Attach user to request (DRY helper)
 */
function attachUser(request: FastifyRequest, user: User): void {
  request.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: user.is_admin,
    is_super_admin: user.is_super_admin,
  };
}

export const ACCESS_COOKIE = 'sb_access';
export const REFRESH_COOKIE = 'sb_refresh';

// Extend FastifyRequest to include user info
declare module 'fastify' {
  interface FastifyRequest {
    user?: {
      id: number;
      username: string;
      email: string;
      is_admin: boolean;
      is_super_admin: boolean;
    };
  }
}

/**
 * Extract the real client IP address from request.
 * Relies on Fastify's trustProxy setting (configured to 1 hop) which
 * securely parses X-Forwarded-For only from trusted proxies.
 * This prevents IP spoofing via untrusted headers.
 */
export function getClientIp(request: FastifyRequest): string {
  return request.ip;
}

/**
 * Extract JWT token from cookie or Authorization header
 */
function extractToken(request: FastifyRequest): string | null {
  const cookieToken = request.cookies?.[ACCESS_COOKIE];
  if (cookieToken) return cookieToken;
  
  const authHeader = request.headers.authorization;
  return AuthService.extractTokenFromHeader(authHeader);
}

/**
 * Modern authentication middleware (2026 standards)
 * - Uses AppError for consistent error handling
 * - LRU cache for performance
 * - Type-safe user attachment
 * - Comprehensive security checks
 */
export async function authMiddleware(request: FastifyRequest): Promise<void> {
  const token = extractToken(request);
  
  if (!token) {
    throw new AppError(401, 'No token provided', 'UNAUTHENTICATED');
  }

  const payload = AuthService.verifyToken(token, 'access');
  if (!payload) {
    throw new AppError(401, 'Token is invalid or expired', 'INVALID_TOKEN');
  }

  if (payload.jti && await store.isAccessTokenBlacklisted(payload.jti)) {
    throw new AppError(401, 'Token has been revoked', 'TOKEN_REVOKED');
  }

  const user = await getUserById(payload.userId);
  if (!user) {
    throw new AppError(401, 'User account not found', 'USER_NOT_FOUND');
  }

  if (!user.is_approved) {
    throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');
  }

  if (user.is_banned) {
    throw new AppError(403, 'Your account has been permanently banned', 'ACCOUNT_BANNED');
  }

  if (user.is_frozen) {
    throw new AppError(403, 'Your account has been temporarily suspended', 'ACCOUNT_FROZEN');
  }

  // Attach user to request (type-safe)
  attachUser(request, user);
}

/**
 * Role-based access control decorators (modern 2026 pattern)
 * Use after authentication in preHandler: [authenticate, requireRole('admin')]
 */

/**
 * Require admin role - assumes authentication already done
 * @throws AppError(403) if not admin
 */
export function requireAdmin(request: FastifyRequest): Promise<void> {
  const u = request.user;
  if (!u) {
    throw new AppError(401, 'Authentication required', 'UNAUTHENTICATED');
  }
  if (!u.is_admin && !u.is_super_admin) {
    throw new AppError(403, 'This action requires administrator privileges', 'FORBIDDEN');
  }
  return Promise.resolve();
}

/**
 * Require super admin role - assumes authentication already done
 * @throws AppError(403) if not super admin
 */
export function requireSuperAdmin(request: FastifyRequest): Promise<void> {
  const u = request.user;
  if (!u) {
    throw new AppError(401, 'Authentication required', 'UNAUTHENTICATED');
  }
  if (!u.is_super_admin) {
    throw new AppError(403, 'This action requires super administrator privileges', 'FORBIDDEN');
  }
  return Promise.resolve();
}

/**
 * Get authenticated user from request or throw
 * Use after authenticate middleware to safely access request.user
 */
export function getAuthUser(request: FastifyRequest) {
  if (!request.user) throw new AppError(401, 'Not authenticated', 'UNAUTHENTICATED');
  return request.user;
}

/**
 * Clear authentication cookies from the response.
 * Clears both domain-scoped and host-only cookie variants
 * to ensure full cleanup regardless of how cookies were originally set.
 */
export function clearAuthCookies(reply: FastifyReply): void {
  const opts = {
    httpOnly: true,
    sameSite: appConfig.NODE_ENV === 'production' ? 'none' as const : 'lax' as const,
    path: '/',
    secure: appConfig.NODE_ENV === 'production',
    domain: appConfig.COOKIE_DOMAIN || undefined,
    expires: new Date(0),
    maxAge: 0,
  };

  reply.setCookie(ACCESS_COOKIE, '', opts);
  reply.setCookie(REFRESH_COOKIE, '', opts);

  // Also clear host-only variants in case cookies were set without domain
  reply.setCookie(ACCESS_COOKIE, '', { ...opts, domain: undefined });
  reply.setCookie(REFRESH_COOKIE, '', { ...opts, domain: undefined });
}
