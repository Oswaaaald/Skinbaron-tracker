import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, baseCookieOptions, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod } from '../../lib/validation-handler.js';
import {
  isProviderEnabled,
  exchangeCodeForUser,
  decryptOAuthState,
  OAUTH_STATE_COOKIE,
  encryptOAuth2FAPending,
  OAUTH_2FA_COOKIE,
  encryptOAuthPendingRegistration,
  OAUTH_PENDING_REG_COOKIE,
} from '../../lib/oauth.js';
import {
  OAuthProviderParamsSchema,
  OAuthCallbackQuerySchema,
} from '../../database/schemas.js';
import { generateUniqueUsername } from '../../lib/username.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthCallbackRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  fastify.get<{ Params: { provider: string }; Querystring: { code?: string; state?: string; error?: string } }>(
    '/oauth/:provider/callback',
    {
      config: { rateLimit: authRateLimitConfig },
      schema: {
        description: 'OAuth callback — exchange authorization code for tokens and log the user in',
        tags: ['Authentication'],
        params: {
          type: 'object',
          required: ['provider'],
          properties: { provider: { type: 'string' } },
        },
        querystring: {
          type: 'object',
          properties: {
            code: { type: 'string' },
            state: { type: 'string' },
            error: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const { provider } = validateWithZod(OAuthProviderParamsSchema, request.params);
      const { code, state, error: oauthError } = validateWithZod(OAuthCallbackQuerySchema, request.query);
      const loginUrl = `${appConfig.CORS_ORIGIN}/login`;

      const fail = (reason: string) => {
        reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
        return reply.redirect(`${loginUrl}?error=${reason}`);
      };

      if (oauthError) return fail('oauth_denied');
      if (!code || !state) return fail('oauth_missing_params');
      if (!isProviderEnabled(provider)) return fail('invalid_provider');

      const stateCookie = request.cookies[OAUTH_STATE_COOKIE];
      if (!stateCookie) return fail('oauth_state_missing');

      let storedState: { state: string; codeVerifier: string; linkUserId?: number; mode?: string };
      try {
        storedState = decryptOAuthState(stateCookie);
      } catch {
        return fail('oauth_state_invalid');
      }

      if (storedState.state !== state) return fail('oauth_state_mismatch');

      let userInfo;
      try {
        userInfo = await exchangeCodeForUser(provider, code, storedState.codeVerifier);
      } catch (err) {
        request.log.error({ err, provider }, 'OAuth code exchange failed');
        return fail('oauth_exchange_failed');
      }

      if (!userInfo.emailVerified) return fail('oauth_email_not_verified');

      if (storedState.linkUserId) {
        const settingsUrl = `${appConfig.CORS_ORIGIN}/settings`;
        const failLink = (reason: string) => {
          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
          return reply.redirect(`${settingsUrl}?link_error=${reason}`);
        };

        try {
          const linkUser = await store.users.findById(storedState.linkUserId);
          if (!linkUser) return failLink('account_not_found');

          const existingOAuth = await store.oauth.findByProviderAccount(provider, userInfo.id);
          if (existingOAuth && existingOAuth.user_id !== linkUser.id) {
            return failLink('already_linked_other');
          }

          if (!existingOAuth) {
            await store.oauth.link(
              linkUser.id,
              provider,
              userInfo.id,
              userInfo.email,
            );

            await store.audit.createLog(
              linkUser.id,
              'oauth_linked',
              JSON.stringify({ provider, provider_email: userInfo.email }),
              getClientIp(request),
              request.headers['user-agent'],
            );
          }

          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
          return reply.redirect(`${appConfig.CORS_ORIGIN}/settings?linked=${provider}`);
        } catch (err) {
          request.log.error({ err, provider }, 'OAuth link flow failed');
          return failLink('server_error');
        }
      }

      try {
        const existingOAuth = await store.oauth.findByProviderAccount(provider, userInfo.id);
        let userId: number;

        if (existingOAuth) {
          const user = await store.users.findById(existingOAuth.user_id);
          if (!user) return fail('oauth_user_not_found');
          if (!user.is_approved) return fail('pending_approval');

          const oauthRestriction = await enforceRestriction(user);
          if (oauthRestriction.result === 'blocked') {
            await store.audit.createLog(
              user.id,
              'login_failed',
              JSON.stringify({ reason: 'account_restricted', method: `oauth_${provider}`, restriction_type: user.restriction_type }),
              getClientIp(request),
              request.headers['user-agent'],
            );
            return fail('account_restricted');
          }

          userId = user.id;

          if (existingOAuth.provider_email !== userInfo.email) {
            await store.oauth.updateProviderEmail(provider, userInfo.id, userInfo.email);
            request.log.info(
              { userId, provider, emailChanged: true },
              'Updated OAuth provider_email after provider-side change',
            );
          }
        } else {
          const existingUser = await store.users.findByEmail(userInfo.email);
          if (existingUser) {
            return fail('oauth_email_taken');
          }

          if (storedState.mode === 'login') {
            return fail('oauth_no_account');
          }

          const suggestedUsername = await generateUniqueUsername(userInfo.name ?? provider);

          reply.setCookie(OAUTH_PENDING_REG_COOKIE, encryptOAuthPendingRegistration({
            provider,
            providerAccountId: userInfo.id,
            email: userInfo.email,
            suggestedUsername,
          }), {
            ...baseCookieOptions(),
            maxAge: 600,
          });

          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
          return reply.redirect(`${appConfig.CORS_ORIGIN}/register?oauth_finalize=pending`);
        }

        const oauthUser = await store.users.findById(userId);
        if (oauthUser?.totp_enabled) {
          reply.setCookie(OAUTH_2FA_COOKIE, encryptOAuth2FAPending(userId, provider), {
            ...baseCookieOptions(),
            maxAge: 5 * 60,
          });

          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
          return reply.redirect(`${appConfig.CORS_ORIGIN}/login?oauth_2fa=pending`);
        }

        const accessToken = AuthService.generateAccessToken(userId);
        const refreshToken = AuthService.generateRefreshToken(userId);
        await store.auth.addRefreshToken(
          userId,
          refreshToken.token,
          refreshToken.jti,
          refreshToken.expiresAt,
          getClientIp(request),
          request.headers['user-agent'],
          accessToken.jti,
        );
        setAuthCookies(reply, accessToken, refreshToken);

        reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());

        await store.audit.createLog(
          userId,
          'login_success',
          JSON.stringify({ method: `oauth_${provider}` }),
          getClientIp(request),
          request.headers['user-agent'],
        );

        return reply.redirect(`${appConfig.CORS_ORIGIN}/?oauth=success`);
      } catch (err) {
        request.log.error({ err, provider }, 'OAuth callback processing failed');
        return fail('oauth_server_error');
      }
    },
  );
}
