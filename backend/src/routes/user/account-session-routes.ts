import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { AuthService } from '../../lib/auth.js';
import {
  getClientIp,
  getAuthUser,
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  clearAuthCookies,
} from '../../lib/middleware.js';
import { handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';

type RegisterUserAccountSessionRoutesOptions = {
  sensitiveOperationRateLimit: {
    max: number;
    timeWindow: string;
    errorResponseBuilder: () => {
      statusCode: number;
      success: boolean;
      error: string;
      message: string;
    };
  };
};

export function registerUserAccountSessionRoutes(
  fastify: FastifyInstance,
  { sensitiveOperationRateLimit }: RegisterUserAccountSessionRoutesOptions,
): void {
  /**
   * GET /api/user/sessions - List active sessions
   */
  fastify.get('/sessions', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'List all active sessions for the current user',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  ip_address: { type: 'string', nullable: true },
                  user_agent: { type: 'string', nullable: true },
                  created_at: { type: 'string' },
                  expires_at: { type: 'string' },
                  is_current: { type: 'boolean' },
                },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const sessions = await store.auth.getActiveSessionsForUser(userId);

      // Identify current session by matching refresh token JTI
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      const data = sessions.map(s => ({
        id: s.id,
        ip_address: s.ip_address,
        user_agent: s.user_agent,
        created_at: s.created_at.toISOString(),
        expires_at: s.expires_at.toISOString(),
        is_current: s.token_jti === currentJti,
      }));

      return reply.status(200).send({ success: true, data });
    } catch (error) {
      return handleRouteError(error, request, reply, 'List sessions');
    }
  });

  /**
   * DELETE /api/user/sessions/:id - Revoke a specific session
   */
  fastify.delete<{ Params: { id: string } }>('/sessions/:id', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Revoke a specific session by ID',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      params: {
        type: 'object',
        properties: { id: { type: 'string', pattern: '^[0-9]+$' } },
        required: ['id'],
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;
      const sessionId = parseInt(request.params.id, 10);

      // Detect if the session being revoked is the current one
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      // Get session info before revoking to check if it's current
      const sessions = await store.auth.getActiveSessionsForUser(userId);
      const targetSession = sessions.find(s => s.id === sessionId);
      const isCurrentSession = targetSession && currentJti && targetSession.token_jti === currentJti;

      const { revoked, accessTokenJti } = await store.auth.revokeSessionById(sessionId, userId);
      if (!revoked) {
        throw new AppError(404, 'Session not found or already revoked', 'SESSION_NOT_FOUND');
      }

      // Blacklist the access token associated with the revoked session
      if (accessTokenJti) {
        // Access tokens expire in 10 min, use a safe upper bound
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await store.auth.blacklistAccessToken(accessTokenJti, userId, accessExpiry, 'session_revoked');
      }

      // If revoking the current session, also blacklist current access token and clear cookies
      let loggedOut = false;
      if (isCurrentSession) {
        const accessToken = AuthService.extractTokenFromHeader(request.headers.authorization ?? '') || request.cookies?.[ACCESS_COOKIE];
        if (accessToken) {
          const tokenPayload = AuthService.verifyToken(accessToken, 'access');
          if (tokenPayload?.jti) {
            const exp = tokenPayload.exp ? tokenPayload.exp * 1000 : Date.now();
            await store.auth.blacklistAccessToken(tokenPayload.jti, userId, exp, 'session_revoked');
          }
        }
        clearAuthCookies(reply);
        loggedOut = true;
      }

      await store.audit.createLog(
        userId,
        'session_revoked',
        JSON.stringify({ method: 'user_self', session_id: sessionId, session_user_agent: targetSession?.user_agent ?? null }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: loggedOut ? 'Current session revoked. You have been logged out.' : 'Session revoked successfully.',
        logged_out: loggedOut,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Revoke session');
    }
  });

  /**
   * DELETE /api/user/sessions - Revoke all other sessions (keep current)
   */
  fastify.delete('/sessions', {
    config: {
      rateLimit: sensitiveOperationRateLimit,
    },
    schema: {
      description: 'Revoke all other sessions — keeps the current session active',
      tags: ['User'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const userId = getAuthUser(request).id;

      // Get current session JTI to preserve it
      const refreshCookie = request.cookies?.[REFRESH_COOKIE];
      let currentJti: string | null = null;
      if (refreshCookie) {
        try {
          const payload = AuthService.verifyToken(refreshCookie, 'refresh');
          currentJti = payload?.jti ?? null;
        } catch {
          // Invalid token, ignore
        }
      }

      if (currentJti) {
        const revokedAccessJtis = await store.auth.revokeAllOtherSessions(userId, currentJti);
        // Blacklist all access tokens from revoked sessions
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await Promise.all(
          revokedAccessJtis.map(jti =>
            store.auth.blacklistAccessToken(jti, userId, accessExpiry, 'other_sessions_revoked')
          )
        );
      } else {
        // Can't identify current session, revoke all + blacklist access tokens
        const revokedJtis = await store.auth.revokeAllForUser(userId);
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, userId, accessExpiry, 'all_sessions_revoked')));
      }

      await store.audit.createLog(
        userId,
        'other_sessions_revoked',
        JSON.stringify({ method: 'user_self' }),
        getClientIp(request),
        request.headers['user-agent'],
      );

      return reply.status(200).send({
        success: true,
        message: 'All other sessions have been revoked.',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Revoke sessions');
    }
  });
}
