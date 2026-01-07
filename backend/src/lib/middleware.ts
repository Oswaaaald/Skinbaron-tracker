import { FastifyRequest, FastifyReply } from 'fastify';
import { AuthService } from './auth.js';

// Extend FastifyRequest to include user info
declare module 'fastify' {
  interface FastifyRequest {
    user?: {
      id: number;
      username: string;
      email: string;
    };
  }
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

    // Attach user to request
    request.user = {
      id: user.id,
      username: user.username,
      email: user.email,
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