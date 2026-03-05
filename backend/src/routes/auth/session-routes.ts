import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, ACCESS_COOKIE, REFRESH_COOKIE, clearAuthCookies, enforceRestriction } from '../../lib/middleware.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  RefreshBodySchema,
  LogoutBodySchema,
} from '../../database/validation-schemas.js';
import type { AuthRoutesContext } from './shared.js';

export function registerSessionAuthRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  fastify.post('/refresh', {
    config: {
      rateLimit: authRateLimitConfig,
    },
    schema: {
      description: 'Refresh access token using a valid refresh token',
      tags: ['Authentication'],
      body: {
        type: 'object',
        properties: {
          refresh_token: { type: 'string' },
        },
        additionalProperties: false,
      },
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                token_expires_at: { type: 'number' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const body = validateWithZod(RefreshBodySchema, request.body ?? {});
      const refresh_token = body.refresh_token || (request.cookies?.[REFRESH_COOKIE]);

      if (!refresh_token) {
        request.log.warn({
          hasCookieHeader: Boolean(request.headers.cookie),
          cookieNames: Object.keys(request.cookies ?? {}),
          hasRefreshCookie: Boolean(request.cookies?.[REFRESH_COOKIE]),
        }, 'Refresh token missing');
        throw new AppError(400, 'Refresh token required', 'REFRESH_TOKEN_MISSING');
      }

      const payload = AuthService.verifyToken(refresh_token, 'refresh');
      if (!payload || !payload.jti) {
        request.log.warn({ hasToken: !!refresh_token }, 'Invalid refresh token signature');
        throw new AppError(401, 'Invalid refresh token', 'INVALID_REFRESH_TOKEN');
      }

      const tokenRecord = await store.auth.getRefreshToken(refresh_token);
      const isExpired = tokenRecord ? tokenRecord.expires_at.getTime() <= Date.now() : true;
      if (!tokenRecord || tokenRecord.revoked_at || tokenRecord.replaced_by_jti || isExpired) {
        // SECURITY: If a replaced token is reused, this is a strong signal of token theft.
        // Revoke ALL tokens for this user to neutralize the stolen token chain.
        if (tokenRecord?.replaced_by_jti) {
          request.log.error({ jti: payload.jti, userId: payload.userId }, 'Refresh token reuse detected — revoking all tokens for user');
          const revokedJtis = await store.auth.revokeAllForUser(payload.userId);
          const accessExpiry = Date.now() + 15 * 60 * 1000;
          await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, payload.userId, accessExpiry, 'token_theft_detected')));
        } else {
          request.log.warn({
            hasRecord: !!tokenRecord,
            isRevoked: tokenRecord?.revoked_at ? true : false,
            isExpired,
            jti: payload.jti
          }, 'Refresh token expired or revoked');
        }
        throw new AppError(401, 'Refresh token expired or revoked', 'REFRESH_TOKEN_EXPIRED');
      }

      // Check moderation status before refreshing
      const refreshUser = await store.users.findById(payload.userId);
      if (!refreshUser) {
        throw new AppError(401, 'User account not found', 'USER_NOT_FOUND');
      }
      if (refreshUser.is_restricted) {
        const restriction = await enforceRestriction(refreshUser);
        if (restriction.result === 'blocked') {
          const revokedJtis = await store.auth.revokeAllForUser(payload.userId);
          const accessExpiry = Date.now() + 15 * 60 * 1000;
          await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, payload.userId, accessExpiry, 'account_restricted')));
          throw new AppError(403, restriction.errorMessage, 'ACCOUNT_RESTRICTED',
            restriction.expiresAt ? { restriction_expires_at: restriction.expiresAt } : undefined);
        }
      }

      // Rotate refresh token
      const newAccess = AuthService.generateAccessToken(payload.userId);
      const newRefresh = AuthService.generateRefreshToken(payload.userId);

      await store.auth.revokeRefreshToken(refresh_token, newRefresh.jti);
      await store.auth.addRefreshToken(payload.userId, newRefresh.token, newRefresh.jti, newRefresh.expiresAt, getClientIp(request), request.headers['user-agent'], newAccess.jti);
      await store.auth.cleanupRefreshTokens();

      setAuthCookies(reply, newAccess, newRefresh);

      return reply.status(200).send({
        success: true,
        data: {
          token_expires_at: newAccess.expiresAt,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Refresh token');
    }
  });

  fastify.post('/logout', {
    preHandler: [fastify.authenticate],
    config: {
      rateLimit: authRateLimitConfig,
    },
    schema: {
      description: 'Logout user and revoke tokens',
      tags: ['Authentication'],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          refresh_token: { type: 'string' },
        },
      },
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
      const authHeader = request.headers.authorization;
      const accessToken = AuthService.extractTokenFromHeader(authHeader ?? '') || (request.cookies?.[ACCESS_COOKIE]);
      const body = validateWithZod(LogoutBodySchema, request.body ?? {});
      const refresh_token = body.refresh_token || (request.cookies?.[REFRESH_COOKIE]);

      const accessPayload = accessToken ? AuthService.verifyToken(accessToken, 'access') : null;

      // Check if user still exists (may have been deleted)
      const userExists = accessPayload ? (await store.users.findById(accessPayload.userId)) !== null : false;

      if (accessPayload?.jti && userExists) {
        const exp = accessPayload.exp ? accessPayload.exp * 1000 : Date.now();
        await store.auth.blacklistAccessToken(accessPayload.jti, accessPayload.userId, exp, 'logout');
      }

      if (refresh_token && userExists) {
        await store.auth.revokeRefreshToken(refresh_token, 'logout');
      } else if (accessPayload && userExists) {
        const revokedJtis = await store.auth.revokeAllForUser(accessPayload.userId);
        const accessExpiry = Date.now() + 15 * 60 * 1000;
        await Promise.all(revokedJtis.map(jti => store.auth.blacklistAccessToken(jti, accessPayload.userId, accessExpiry, 'logout')));
      }

      // Clean up revoked tokens from database
      await store.auth.cleanupRefreshTokens();

      if (accessPayload && userExists) {
        await store.audit.createLog(
          accessPayload.userId,
          'logout',
          JSON.stringify({ reason: 'user_logout' }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }

      clearAuthCookies(reply);

      return reply.status(200).send({ success: true, message: 'Logged out' });
    } catch (error) {
      return handleRouteError(error, request, reply, 'User logout');
    }
  });
}
