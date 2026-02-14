import { FastifyRequest } from 'fastify';
import '@fastify/cookie';
import { LRUCache } from 'lru-cache';
import { AuthService } from './auth.js';
import { store } from '../database/index.js';
import type { User } from '../database/schemas.js';
import { AppError } from './errors.js';

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
function getUserById(id: number): User | null {
  const cached = userCache.get(id);
  if (cached) return cached;

  const user = store.getUserById(id);

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
    is_admin: Boolean(user.is_admin),
    is_super_admin: Boolean(user.is_super_admin),
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
export function authMiddleware(request: FastifyRequest): Promise<void> {
  const token = extractToken(request);
  
  if (!token) {
    throw new AppError(401, 'No token provided', 'UNAUTHENTICATED');
  }

  const payload = AuthService.verifyToken(token, 'access');
  if (!payload) {
    throw new AppError(401, 'Token is invalid or expired', 'INVALID_TOKEN');
  }

  if (payload.jti && store.isAccessTokenBlacklisted(payload.jti)) {
    throw new AppError(401, 'Token has been revoked', 'TOKEN_REVOKED');
  }

  const user = getUserById(payload.userId);
  if (!user) {
    throw new AppError(401, 'User account not found', 'USER_NOT_FOUND');
  }

  if (!user.is_approved) {
    throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');
  }

  // Attach user to request (type-safe)
  attachUser(request, user);
  return Promise.resolve();
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

