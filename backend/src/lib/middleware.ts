import { FastifyRequest, FastifyReply } from 'fastify';
import '@fastify/cookie';
import { LRUCache } from 'lru-cache';
import { AuthService } from './auth.js';
import { getStore, User } from './store.js';
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
async function getUserById(id: number): Promise<User | null> {
  const cached = userCache.get(id);
  if (cached) return cached;

  const store = getStore();
  const user = store.getUserById(id);

  if (user) {
    userCache.set(id, user);
  }

  return user;
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
 * Extract the real client IP address from request headers
 * Handles CF-Connecting-IP (Cloudflare), X-Real-IP, X-Forwarded-For, and falls back to request.ip
 */
export function getClientIp(request: FastifyRequest): string {
  // Check CF-Connecting-IP header (Cloudflare specific - most reliable)
  const cfConnectingIp = request.headers['cf-connecting-ip'];
  if (cfConnectingIp && typeof cfConnectingIp === 'string') {
    return cfConnectingIp;
  }

  // Check X-Real-IP header
  const xRealIp = request.headers['x-real-ip'];
  if (xRealIp && typeof xRealIp === 'string') {
    return xRealIp;
  }

  // Check X-Forwarded-For header (proxy chain)
  const xForwardedFor = request.headers['x-forwarded-for'];
  if (xForwardedFor) {
    // Take the first IP in the chain (the original client)
    const ips = typeof xForwardedFor === 'string' 
      ? xForwardedFor.split(',').map(ip => ip.trim())
      : xForwardedFor;
    if (ips.length > 0 && ips[0]) {
      return ips[0];
    }
  }

  // Fall back to Fastify's request.ip
  return request.ip;
}

/**
 * Extract JWT token from cookie or Authorization header
 */
function extractToken(request: FastifyRequest): string | null {
  const cookieToken = request.cookies?.[ACCESS_COOKIE] as string | undefined;
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
export async function authMiddleware(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  const token = extractToken(request);
  
  if (!token) {
    throw new AppError(401, 'No token provided', 'UNAUTHENTICATED');
  }

  const payload = AuthService.verifyToken(token, 'access');
  if (!payload) {
    throw new AppError(401, 'Token is invalid or expired', 'INVALID_TOKEN');
  }

  const store = getStore();
  if (payload.jti && store.isAccessTokenBlacklisted(payload.jti)) {
    throw new AppError(401, 'Token has been revoked', 'TOKEN_REVOKED');
  }

  const user = await getUserById(payload.userId);
  if (!user) {
    throw new AppError(401, 'User account not found', 'USER_NOT_FOUND');
  }

  if (!user.is_approved) {
    throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');
  }

  // Attach user to request (type-safe)
  request.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: Boolean(user.is_admin),
    is_super_admin: Boolean(user.is_super_admin),
  };
}

/**
 * Role-based access control decorators (modern 2026 pattern)
 * Use after authentication in preHandler: [authenticate, requireRole('admin')]
 */

/**
 * Require admin role - assumes authentication already done
 * @throws AppError(401) if not authenticated
 * @throws AppError(403) if not admin
 */
export async function requireAdmin(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  if (!request.user) {
    throw new AppError(401, 'Authentication required', 'UNAUTHENTICATED');
  }
  
  if (!request.user.is_admin) {
    throw new AppError(403, 'This action requires administrator privileges', 'FORBIDDEN');
  }
}

/**
 * Require super admin role - assumes authentication already done
 * @throws AppError(401) if not authenticated
 * @throws AppError(403) if not super admin
 */
export async function requireSuperAdmin(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  if (!request.user) {
    throw new AppError(401, 'Authentication required', 'UNAUTHENTICATED');
  }
  
  if (!request.user.is_super_admin) {
    throw new AppError(403, 'This action requires super administrator privileges', 'FORBIDDEN');
  }
}

/**
 * Optional authentication middleware (allows anonymous access)
 * Attaches user to request if valid token provided, but doesn't fail if missing
 */
export async function optionalAuthMiddleware(request: FastifyRequest, _reply: FastifyReply): Promise<void> {
  try {
    const token = extractToken(request);
    if (!token) return;

    const payload = AuthService.verifyToken(token, 'access');
    if (!payload) return;

    const store = getStore();
    if (payload.jti && store.isAccessTokenBlacklisted(payload.jti)) return;

    const user = await getUserById(payload.userId);
    if (!user || !user.is_approved) return;

    request.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: Boolean(user.is_admin),
      is_super_admin: Boolean(user.is_super_admin),
    };
  } catch (error) {
    // Log but don't fail - optional auth
    request.log.debug({ error }, 'Optional authentication failed');
  }
}