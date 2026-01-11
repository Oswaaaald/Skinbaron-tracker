import { FastifyRequest, FastifyReply } from 'fastify';
import { AuthService } from './auth.js';

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
 * Handles X-Forwarded-For, X-Real-IP, and falls back to request.ip
 */
export function getClientIp(request: FastifyRequest): string {
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

  // Check X-Real-IP header
  const xRealIp = request.headers['x-real-ip'];
  if (xRealIp && typeof xRealIp === 'string') {
    return xRealIp;
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

// Get user from store
async function getUserById(id: number): Promise<any> {
  const { getStore } = await import('./store.js');
  const store = getStore();
  return store.getUserById(id);
}