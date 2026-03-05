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

      let userId: number | null = null;
      const accessJtis = new Set<string>();
      const jtiExpiry = new Map<string, number>();

      const accessPayload = accessToken ? AuthService.verifyToken(accessToken, 'access') : null;
      if (accessPayload?.jti) {
        userId = accessPayload.userId;
        accessJtis.add(accessPayload.jti);
        jtiExpiry.set(accessPayload.jti, accessPayload.exp ? accessPayload.exp * 1000 : Date.now() + 15 * 60 * 1000);
      }

      if (refresh_token) {
        const refreshPayload = AuthService.verifyToken(refresh_token, 'refresh');
        if (refreshPayload?.userId && userId === null) {
          userId = refreshPayload.userId;
        }

        const refreshRecord = await store.auth.getRefreshToken(refresh_token);
        if (refreshRecord?.user_id && userId === null) {
          userId = refreshRecord.user_id;
        }

        if (refreshRecord && !refreshRecord.revoked_at) {
          await store.auth.revokeRefreshToken(refresh_token, 'logout');
        }

        if (refreshRecord?.access_token_jti) {
          accessJtis.add(refreshRecord.access_token_jti);
          jtiExpiry.set(refreshRecord.access_token_jti, Date.now() + 15 * 60 * 1000);
        }
      }

      if (userId !== null) {
        const revokedJtis = await store.auth.revokeAllForUser(userId);
        for (const jti of revokedJtis) {
          accessJtis.add(jti);
          if (!jtiExpiry.has(jti)) {
            jtiExpiry.set(jti, Date.now() + 15 * 60 * 1000);
          }
        }

        await Promise.all(
          Array.from(accessJtis).map((jti) =>
            store.auth.blacklistAccessToken(jti, userId, jtiExpiry.get(jti) ?? Date.now() + 15 * 60 * 1000, 'logout')
          ),
        );

        await store.audit.createLog(
          userId,
          'logout',
          JSON.stringify({ reason: 'user_logout' }),
          getClientIp(request),
          request.headers['user-agent']
        );
      }

      // Best-effort hygiene even when scheduler is disabled.
      await Promise.all([
        store.auth.cleanupRefreshTokens(),
        store.auth.cleanupExpiredBlacklistTokens(),
        store.challenges.cleanup(),
      ]);

      clearAuthCookies(reply);

      return reply.status(200).send({ success: true, message: 'Logged out' });
    } catch (error) {
      clearAuthCookies(reply);
      return handleRouteError(error, request, reply, 'User logout');
    }
  });
}
