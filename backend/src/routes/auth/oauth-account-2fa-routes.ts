import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, baseCookieOptions, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  decryptOAuth2FAPending,
  OAUTH_2FA_COOKIE,
} from '../../lib/oauth.js';
import { VerifyOAuth2FASchema } from '../../database/schemas.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthTwoFactorRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  fastify.post<{ Body: { totp_code: string } }>(
    '/verify-oauth-2fa',
    {
      config: { rateLimit: authRateLimitConfig },
      schema: {
        description: 'Verify 2FA code after OAuth login for users with TOTP enabled',
        tags: ['Authentication'],
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['totp_code'],
          properties: {
            totp_code: { type: 'string', minLength: 6, maxLength: 8 },
          },
        },
        response: {
          200: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: {
                type: 'object',
                properties: {
                  id: { type: 'number' },
                  username: { type: 'string' },
                  email: { type: 'string' },
                  avatar_url: { type: 'string' },
                  is_admin: { type: 'boolean' },
                  is_super_admin: { type: 'boolean' },
                },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        const { totp_code } = validateWithZod(VerifyOAuth2FASchema, request.body);
        const pendingCookie = request.cookies[OAUTH_2FA_COOKIE];

        if (!pendingCookie) {
          throw new AppError(401, 'No pending 2FA challenge. Please try logging in again.', 'OAUTH_2FA_EXPIRED');
        }

        let pending: { userId: number; provider: string };
        try {
          pending = decryptOAuth2FAPending(pendingCookie);
        } catch {
          reply.clearCookie(OAUTH_2FA_COOKIE, baseCookieOptions());
          throw new AppError(401, '2FA challenge has expired. Please try logging in again.', 'OAUTH_2FA_EXPIRED');
        }

        const user = await store.users.findById(pending.userId, true);
        if (!user || !user.totp_enabled) {
          throw new AppError(401, 'User not found or 2FA no longer active.', 'OAUTH_2FA_INVALID');
        }

        await verifyTotpOrRecoveryCode(user, totp_code, request, `oauth_${pending.provider}`);

        const oauth2faRestriction = await enforceRestriction(user);
        if (oauth2faRestriction.result === 'blocked') {
          await store.audit.createLog(
            user.id,
            'login_failed',
            JSON.stringify({ reason: 'account_restricted', method: `oauth_${pending.provider}`, restriction_type: user.restriction_type }),
            getClientIp(request),
            request.headers['user-agent'],
          );
          throw new AppError(
            403,
            oauth2faRestriction.errorMessage,
            'ACCOUNT_RESTRICTED',
            oauth2faRestriction.expiresAt ? { restriction_expires_at: oauth2faRestriction.expiresAt } : undefined,
          );
        }

        const accessToken = AuthService.generateAccessToken(user.id);
        const refreshToken = AuthService.generateRefreshToken(user.id);
        await store.auth.addRefreshToken(
          user.id,
          refreshToken.token,
          refreshToken.jti,
          refreshToken.expiresAt,
          getClientIp(request),
          request.headers['user-agent'],
          accessToken.jti,
        );
        setAuthCookies(reply, accessToken, refreshToken);

        reply.clearCookie(OAUTH_2FA_COOKIE, baseCookieOptions());

        await store.audit.createLog(
          user.id,
          'login_success',
          JSON.stringify({ method: `oauth_${pending.provider}`, '2fa': true }),
          getClientIp(request),
          request.headers['user-agent'],
        );

        return reply.status(200).send({
          success: true,
          data: {
            id: user.id,
            username: user.username,
            email: user.email,
            avatar_url: AuthService.getAvatarUrl(user, appConfig.NEXT_PUBLIC_API_URL),
            use_gravatar: user.use_gravatar,
            is_admin: user.is_admin,
            is_super_admin: user.is_super_admin,
            has_password: !!user.password_hash,
          },
        });
      } catch (error) {
        return handleRouteError(error, request, reply, 'verify-oauth-2fa');
      }
    },
  );
}
