import type { FastifyInstance } from 'fastify';
import { AuthService } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, baseCookieOptions } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import {
  decryptOAuthPendingRegistration,
  OAUTH_PENDING_REG_COOKIE,
} from '../../lib/oauth.js';
import { FinalizeOAuthRegistrationSchema } from '../../database/schemas.js';
import type { AuthRoutesContext } from './shared.js';

export function registerOAuthPendingRegistrationRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
  const pendingRegCookieOptions = baseCookieOptions();

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

        const existingUsername = await store.users.findByUsername(username);
        if (existingUsername) {
          throw new AppError(409, 'This username is already taken', 'USERNAME_TAKEN');
        }

        const existingEmail = await store.users.findByEmail(pending.email);
        if (existingEmail) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(409, 'An account with this email was created while you were registering. Please try logging in.', 'EMAIL_TAKEN');
        }

        if (await store.isEmailBanned(pending.email)) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(403, 'This email address is not allowed', 'EMAIL_BANNED');
        }

        const existingOAuth = await store.oauth.findByProviderAccount(pending.provider, pending.providerAccountId);
        if (existingOAuth) {
          reply.clearCookie(OAUTH_PENDING_REG_COOKIE, pendingRegCookieOptions);
          throw new AppError(409, 'This social account is already linked. Please try logging in.', 'OAUTH_ALREADY_LINKED');
        }

        const newUser = await store.users.create({ username, email: pending.email });

        if (!newUser.is_approved) {
          await store.users.update(newUser.id, { is_approved: true });
        }

        await store.users.acceptTos(newUser.id);

        await store.oauth.link(
          newUser.id,
          pending.provider,
          pending.providerAccountId,
          pending.email,
        );

        await store.audit.createLog(
          newUser.id,
          'oauth_register',
          JSON.stringify({ provider: pending.provider, provider_email: pending.email }),
          getClientIp(request),
          request.headers['user-agent'],
        );

        const accessToken = AuthService.generateAccessToken(newUser.id);
        const refreshToken = AuthService.generateRefreshToken(newUser.id);
        await store.auth.addRefreshToken(
          newUser.id,
          refreshToken.token,
          refreshToken.jti,
          refreshToken.expiresAt,
          getClientIp(request),
          request.headers['user-agent'],
          accessToken.jti,
        );
        setAuthCookies(reply, accessToken, refreshToken);

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
}
