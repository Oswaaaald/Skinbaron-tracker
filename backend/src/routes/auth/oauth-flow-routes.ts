import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, ACCESS_COOKIE, baseCookieOptions, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  getEnabledProviders, isProviderEnabled,
  createAuthorizationUrl, exchangeCodeForUser,
  encryptOAuthState, decryptOAuthState, OAUTH_STATE_COOKIE,
  encryptOAuth2FAPending, OAUTH_2FA_COOKIE,
  encryptOAuthPendingRegistration, OAUTH_PENDING_REG_COOKIE,
} from '../../lib/oauth.js';
import {
  OAuthProviderParamsSchema,
  OAuthProviderQuerySchema,
  OAuthCallbackQuerySchema,
} from '../../database/schemas.js';
import { generateUniqueUsername } from '../../lib/username.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthFlowRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  /**
   * Get list of enabled OAuth providers
   */
  fastify.get('/oauth/providers', {
    schema: {
      description: 'Get list of enabled OAuth providers',
      tags: ['Authentication'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                providers: { type: 'array', items: { type: 'string' } },
              },
            },
          },
        },
      },
    },
  }, async (_request, reply) => {
    return reply.send({
      success: true,
      data: { providers: getEnabledProviders() },
    });
  });

  /**
   * Initiate OAuth flow — redirect to provider authorization page
   */
  fastify.get<{ Params: { provider: string }; Querystring: { mode?: string } }>('/oauth/:provider', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Initiate OAuth flow — redirects to provider authorization page',
      tags: ['Authentication'],
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
      querystring: {
        type: 'object',
        properties: { mode: { type: 'string', enum: ['login', 'register'] } },
      },
    },
  }, async (request, reply) => {
    const { provider } = validateWithZod(OAuthProviderParamsSchema, request.params);
    const { mode } = validateWithZod(OAuthProviderQuerySchema, request.query);

    if (!isProviderEnabled(provider)) {
      throw new AppError(400, `OAuth provider "${provider}" is not available`, 'INVALID_PROVIDER');
    }

    // Detect if user is already logged in (linking flow vs login flow)
    let linkUserId: number | undefined;
    try {
      const token = request.cookies?.[ACCESS_COOKIE] || AuthService.extractTokenFromHeader(request.headers.authorization ?? '');
      if (token) {
        const payload = AuthService.verifyToken(token, 'access');
        if (payload?.userId) linkUserId = payload.userId;
      }
    } catch {
      // not logged in — normal login flow
    }

    const { url, state, codeVerifier } = createAuthorizationUrl(provider);

    // Store state + codeVerifier (+ linkUserId if linking, + mode) in encrypted HttpOnly cookie
    reply.setCookie(OAUTH_STATE_COOKIE, encryptOAuthState(state, codeVerifier, linkUserId, mode), {
      ...baseCookieOptions(),
      maxAge: 600, // 10 minutes
    });

    return reply.redirect(url.toString());
  });

  /**
   * OAuth callback — exchange authorization code for tokens and log the user in
   */
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

      // Helper to redirect with error and clean the state cookie
      const fail = (reason: string) => {
        reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
        return reply.redirect(`${loginUrl}?error=${reason}`);
      };

      // --- Pre-flight checks ---
      if (oauthError) return fail('oauth_denied');
      if (!code || !state) return fail('oauth_missing_params');
      if (!isProviderEnabled(provider)) return fail('invalid_provider');

      // Read and validate encrypted state cookie
      const stateCookie = request.cookies[OAUTH_STATE_COOKIE];
      if (!stateCookie) return fail('oauth_state_missing');

      let storedState: { state: string; codeVerifier: string; linkUserId?: number; mode?: string };
      try {
        storedState = decryptOAuthState(stateCookie);
      } catch {
        return fail('oauth_state_invalid');
      }

      if (storedState.state !== state) return fail('oauth_state_mismatch');

      // --- Exchange code for user info ---
      let userInfo;
      try {
        userInfo = await exchangeCodeForUser(provider, code, storedState.codeVerifier);
      } catch (err) {
        request.log.error({ err, provider }, 'OAuth code exchange failed');
        return fail('oauth_exchange_failed');
      }

      if (!userInfo.emailVerified) return fail('oauth_email_not_verified');

      // --- Link flow (user was logged in when they initiated OAuth) ---
      if (storedState.linkUserId) {
        // For link flow, errors redirect to settings page (not login)
        const settingsUrl = `${appConfig.CORS_ORIGIN}/settings`;
        const failLink = (reason: string) => {
          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
          return reply.redirect(`${settingsUrl}?link_error=${reason}`);
        };

        try {
          const linkUser = await store.users.findById(storedState.linkUserId);
          if (!linkUser) return failLink('account_not_found');

          // Check if this provider account is already linked to a DIFFERENT user
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

          // Clean state cookie and redirect to settings
          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());

          return reply.redirect(`${appConfig.CORS_ORIGIN}/settings?linked=${provider}`);
        } catch (err) {
          request.log.error({ err, provider }, 'OAuth link flow failed');
          return failLink('server_error');
        }
      }

      // --- Login / Register flow (user was NOT logged in) ---
      try {
        // 1. Check if this OAuth account is already linked
        const existingOAuth = await store.oauth.findByProviderAccount(provider, userInfo.id);
        let userId: number;

        if (existingOAuth) {
          // Already linked -> verify user
          const user = await store.users.findById(existingOAuth.user_id);
          if (!user) return fail('oauth_user_not_found');
          if (!user.is_approved) return fail('pending_approval');

          // Check restriction status (consistent with password & passkey login)
          const oauthRestriction = await enforceRestriction(user);
          if (oauthRestriction.result === 'blocked') {
            await store.audit.createLog(user.id, 'login_failed', JSON.stringify({ reason: 'account_restricted', method: `oauth_${provider}`, restriction_type: user.restriction_type }), getClientIp(request), request.headers['user-agent']);
            return fail('account_restricted');
          }

          userId = user.id;

          // Keep provider_email in sync if user changed their email on the provider
          if (existingOAuth.provider_email !== userInfo.email) {
            await store.oauth.updateProviderEmail(provider, userInfo.id, userInfo.email);
            request.log.info(
              { userId, provider, emailChanged: true },
              'Updated OAuth provider_email after provider-side change',
            );
          }
        } else {
          // 2. Check if a user with the same email already exists
          const existingUser = await store.users.findByEmail(userInfo.email);

          if (existingUser) {
            // Account exists but OAuth is not linked -> user must log in and link manually
            // This is the industry-standard approach (GitHub, GitLab, Stripe, etc.)
            // to prevent account takeover via email matching.
            return fail('oauth_email_taken');
          }

          // 3. No existing user — only allow registration if not in login-only mode
          if (storedState.mode === 'login') {
            return fail('oauth_no_account');
          }

          // Defer account creation: store OAuth info in encrypted cookie
          // and redirect to finalization page where user accepts TOS + picks username
          const suggestedUsername = await generateUniqueUsername(userInfo.name ?? provider);

          reply.setCookie(OAUTH_PENDING_REG_COOKIE, encryptOAuthPendingRegistration({
            provider,
            providerAccountId: userInfo.id,
            email: userInfo.email,
            suggestedUsername,
          }), {
            ...baseCookieOptions(),
            maxAge: 600, // 10 minutes
          });

          // Clean state cookie
          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());

          return reply.redirect(`${appConfig.CORS_ORIGIN}/register?oauth_finalize=pending`);
        }

        // --- Check if 2FA is required before issuing tokens ---
        const oauthUser = await store.users.findById(userId);
        if (oauthUser?.totp_enabled) {
          // Set a short-lived encrypted pending-2FA cookie
          reply.setCookie(OAUTH_2FA_COOKIE, encryptOAuth2FAPending(userId, provider), {
            ...baseCookieOptions(),
            maxAge: 5 * 60, // 5 minutes
          });

          // Clean state cookie
          reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());

          // Redirect to login page with 2FA challenge
          return reply.redirect(`${appConfig.CORS_ORIGIN}/login?oauth_2fa=pending`);
        }

        // --- Issue JWT tokens ---
        const accessToken = AuthService.generateAccessToken(userId);
        const refreshToken = AuthService.generateRefreshToken(userId);
        await store.auth.addRefreshToken(userId, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
        setAuthCookies(reply, accessToken, refreshToken);

        // Clean state cookie
        reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());

        await store.audit.createLog(
          userId,
          'login_success',
          JSON.stringify({ method: `oauth_${provider}` }),
          getClientIp(request),
          request.headers['user-agent'],
        );

        // Redirect to frontend dashboard
        return reply.redirect(`${appConfig.CORS_ORIGIN}/?oauth=success`);
      } catch (err) {
        request.log.error({ err, provider }, 'OAuth callback processing failed');
        return fail('oauth_server_error');
      }
    },
  );
}
