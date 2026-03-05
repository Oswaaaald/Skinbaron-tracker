import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, baseCookieOptions, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  decryptOAuth2FAPending, OAUTH_2FA_COOKIE,
  decryptOAuthPendingRegistration, OAUTH_PENDING_REG_COOKIE,
} from '../../lib/oauth.js';
import {
  FinalizeOAuthRegistrationSchema,
  VerifyOAuth2FASchema,
} from '../../database/schemas.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthAccountRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  const pendingRegCookieOptions = baseCookieOptions();

  /**
   * Get pending OAuth registration info (email, suggested username, provider).
   * Reads the encrypted pending-reg cookie set during OAuth callback.
   */
  fastify.get('/oauth-pending-registration', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Get pending OAuth registration data (email, suggested username)',
      tags: ['Authentication'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                email: { type: 'string' },
                suggested_username: { type: 'string' },
                provider: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const cookie = request.cookies[OAUTH_PENDING_REG_COOKIE];
      if (!cookie) {
        throw new AppError(401, 'No pending OAuth registration. Please start the sign-up process again.', 'OAUTH_PENDING_REG_MISSING');
      }

      let pending;
      try {
        pending = decryptOAuthPendingRegistration(cookie);
      } catch {
        reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
        throw new AppError(401, 'OAuth registration session has expired. Please try again.', 'OAUTH_PENDING_REG_EXPIRED');
      }

      return reply.status(200).send({
        success: true,
        data: {
          email: pending.email,
          suggested_username: pending.suggestedUsername,
          provider: pending.provider,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'oauth-pending-registration');
    }
  });

  /**
   * Finalize OAuth registration — create the account after user accepts TOS and picks username.
   * Reads the encrypted pending-reg cookie, creates user + links OAuth + accepts TOS.
   */
  fastify.post<{ Body: { username: string; tos_accepted: boolean } }>(
    '/finalize-oauth-registration',
    {
      config: { rateLimit: authRateLimitConfig },
      schema: {
        description: 'Finalize OAuth registration with TOS acceptance and username',
        tags: ['Authentication'],
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['username', 'tos_accepted'],
          properties: {
            username: { type: 'string', minLength: 3, maxLength: 20, pattern: '^[a-zA-Z0-9_]+$' },
            tos_accepted: { type: 'boolean' },
          },
        },
        response: {
          201: {
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
        const { username } = validateWithZod(FinalizeOAuthRegistrationSchema, request.body);

        // Read pending registration cookie
        const cookie = request.cookies[OAUTH_PENDING_REG_COOKIE];
        if (!cookie) {
          throw new AppError(401, 'No pending OAuth registration. Please start the sign-up process again.', 'OAUTH_PENDING_REG_MISSING');
        }

        let pending;
        try {
          pending = decryptOAuthPendingRegistration(cookie);
        } catch {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(401, 'OAuth registration session has expired. Please try again.', 'OAUTH_PENDING_REG_EXPIRED');
        }

        // Check username availability
        const existingUsername = await store.users.findByUsername(username);
        if (existingUsername) {
          throw new AppError(409, 'This username is already taken', 'USERNAME_TAKEN');
        }

        // Double-check email not taken since cookie was issued
        const existingEmail = await store.users.findByEmail(pending.email);
        if (existingEmail) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(409, 'An account with this email was created while you were registering. Please try logging in.', 'EMAIL_TAKEN');
        }

        // Check if email is banned
        if (await store.isEmailBanned(pending.email)) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(403, 'This email address is not allowed', 'EMAIL_BANNED');
        }

        // Double-check OAuth account not taken
        const existingOAuth = await store.oauth.findByProviderAccount(pending.provider, pending.providerAccountId);
        if (existingOAuth) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(409, 'This social account is already linked. Please try logging in.', 'OAUTH_ALREADY_LINKED');
        }

        // --- Create the account ---
        const newUser = await store.users.create({ username, email: pending.email });

        // Auto-approve OAuth users
        if (!newUser.is_approved) {
          await store.users.update(newUser.id, { is_approved: true });
        }

        // Record TOS acceptance
        await store.users.acceptTos(newUser.id);

        // Link OAuth account
        await store.oauth.link(
          newUser.id,
          pending.provider,
          pending.providerAccountId,
          pending.email,
        );

        // Audit log
        await store.audit.createLog(
          newUser.id,
          'oauth_register',
          JSON.stringify({ provider: pending.provider, provider_email: pending.email }),
          getClientIp(request),
          request.headers['user-agent'],
        );

        // Issue JWT tokens
        const accessToken = AuthService.generateAccessToken(newUser.id);
        const refreshToken = AuthService.generateRefreshToken(newUser.id);
        await store.auth.addRefreshToken(newUser.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
        setAuthCookies(reply, accessToken, refreshToken);

        // Clean pending-reg cookie
        reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);

        return reply.status(201).send({
          success: true,
          data: {
            id: newUser.id,
            username: newUser.username,
            email: newUser.email,
            avatar_url: AuthService.getAvatarUrl(newUser, appConfig.NEXT_PUBLIC_API_URL),
            use_gravatar: newUser.use_gravatar,
            is_admin: newUser.is_admin,
            is_super_admin: newUser.is_super_admin,
            has_password: !!newUser.password_hash,
          },
        });
      } catch (error) {
        return handleRouteError(error, request, reply, 'finalize-oauth-registration');
      }
    },
  );

  /**
   * Verify 2FA code after an OAuth login for users with TOTP enabled.
   * Reads the encrypted pending-2FA cookie, verifies the TOTP code,
   * and issues JWT tokens on success.
   */
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
          // Clear invalid cookie
          reply.clearCookie(OAUTH_2FA_COOKIE, baseCookieOptions());
          throw new AppError(401, '2FA challenge has expired. Please try logging in again.', 'OAUTH_2FA_EXPIRED');
        }

        // Fetch user with decrypted 2FA secrets (single query)
        const user = await store.users.findById(pending.userId, true);
        if (!user || !user.totp_enabled) {
          throw new AppError(401, 'User not found or 2FA no longer active.', 'OAUTH_2FA_INVALID');
        }

        // Verify TOTP code or recovery code (shared logic)
        await verifyTotpOrRecoveryCode(user, totp_code, request, `oauth_${pending.provider}`);

        // Check restriction status (user may have been restricted between OAuth redirect and 2FA verification)
        const oauth2faRestriction = await enforceRestriction(user);
        if (oauth2faRestriction.result === 'blocked') {
          await store.audit.createLog(user.id, 'login_failed', JSON.stringify({ reason: 'account_restricted', method: `oauth_${pending.provider}`, restriction_type: user.restriction_type }), getClientIp(request), request.headers['user-agent']);
          throw new AppError(403, oauth2faRestriction.errorMessage, 'ACCOUNT_RESTRICTED',
            oauth2faRestriction.expiresAt ? { restriction_expires_at: oauth2faRestriction.expiresAt } : undefined);
        }

        // --- 2FA verified, issue JWT tokens ---
        const accessToken = AuthService.generateAccessToken(user.id);
        const refreshToken = AuthService.generateRefreshToken(user.id);
        await store.auth.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
        setAuthCookies(reply, accessToken, refreshToken);

        // Clear the pending 2FA cookie
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
