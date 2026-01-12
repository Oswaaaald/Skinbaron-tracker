import { FastifyRequest, FastifyReply } from 'fastify';
import { AuthService } from './auth.js';

type CachedUser = {
  user: any;
  expiresAt: number;
};

const userCache = new Map<number, CachedUser>();
const USER_CACHE_TTL_MS = 30_000;
const USER_CACHE_MAX = 200;

function getCachedUser(id: number): any | null {
  const cached = userCache.get(id);
  if (!cached) return null;
  if (cached.expiresAt < Date.now()) {
    userCache.delete(id);
    return null;
  }
  return cached.user;
}

function setCachedUser(id: number, user: any) {
  if (userCache.size >= USER_CACHE_MAX) {
    // Drop the oldest entry (Map preserves insertion order)
    const oldestKey = userCache.keys().next().value;
    if (oldestKey !== undefined) {
      userCache.delete(oldestKey);
    }
  }
  userCache.set(id, { user, expiresAt: Date.now() + USER_CACHE_TTL_MS });
}

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
 * Authentication middleware
 */
export async function authMiddleware(request: FastifyRequest, reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization;
    const token = AuthService.extractTokenFromHeader(authHeader);
    
    if (!token) {
      return reply.status(401).send({
        success: false,
        error: 'Authentication required',
        message: 'No token provided',
      });
    }

    const payload = AuthService.verifyToken(token);
    if (!payload) {
      return reply.status(401).send({
        success: false,
        error: 'Invalid token',
        message: 'Token is invalid or expired',
      });
    }

    // Get user from database (we'll implement this)
    const user = await getUserById(payload.userId);
    if (!user) {
      return reply.status(401).send({
        success: false,
        error: 'User not found',
        message: 'Token references non-existent user',
      });
    }

    // Check if user is approved
    if (!user.is_approved) {
      return reply.status(403).send({
        success: false,
        error: 'Account pending approval',
        message: 'Your account is awaiting admin approval',
      });
    }

    // Attach user to request
    request.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: user.is_admin || false,
      is_super_admin: user.is_super_admin || false,
    };

  } catch (error) {
    return reply.status(500).send({
      success: false,
      error: 'Authentication error',
      message: 'Internal authentication error',
    });
  }
}

/**
 * Admin authentication middleware - requires is_admin === true
 */
export async function requireAdminMiddleware(request: FastifyRequest, reply: FastifyReply) {
  // First check normal authentication
  await authMiddleware(request, reply);
  
  // If auth failed, the reply was already sent
  if (reply.sent) {
    return;
  }
  
  // Check admin status
  if (!request.user?.is_admin) {
    return reply.status(403).send({
      success: false,
      error: 'Admin access required',
      message: 'This action requires administrator privileges',
    });
  }
}

/**
 * Super Admin authentication middleware - requires is_super_admin === true
 */
export async function requireSuperAdminMiddleware(request: FastifyRequest, reply: FastifyReply) {
  // First check normal authentication
  await authMiddleware(request, reply);
  
  // If auth failed, the reply was already sent
  if (reply.sent) {
    return;
  }
  
  // Check super admin status
  if (!request.user?.is_super_admin) {
    return reply.status(403).send({
      success: false,
      error: 'Super Admin access required',
      message: 'This action requires super administrator privileges',
    });
  }
}

/**
 * Optional auth middleware (allows anonymous access)
 */
export async function optionalAuthMiddleware(request: FastifyRequest, _reply: FastifyReply) {
  try {
    const authHeader = request.headers.authorization;
    const token = AuthService.extractTokenFromHeader(authHeader);
    
    if (token) {
      const payload = AuthService.verifyToken(token);
      if (payload) {
        const user = await getUserById(payload.userId);
        if (user) {
          request.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            is_admin: user.is_admin || false,
            is_super_admin: user.is_super_admin || false,
          };
        }
      }
    }
    // Continue without error if no auth
  } catch (error) {
    // Log error but continue
  }
}

// Get user from store with short-lived cache to cut DB traffic
async function getUserById(id: number): Promise<any> {
  const cached = getCachedUser(id);
  if (cached) return cached;

  const { getStore } = await import('./store.js');
  const store = getStore();
  const user = store.getUserById(id);

  if (user) {
    setCachedUser(id, user);
  } else {
    userCache.delete(id);
  }

  return user;
}