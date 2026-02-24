import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { store } from '../database/index.js';
import { getClientIp, ACCESS_COOKIE, REFRESH_COOKIE, clearAuthCookies, baseCookieOptions, enforceRestriction } from '../lib/middleware.js';
import { appConfig } from '../lib/config.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { OTP } from 'otplib';
import crypto from 'crypto';
import {
  getEnabledProviders, isProviderEnabled,
  createAuthorizationUrl, exchangeCodeForUser,
  encryptOAuthState, decryptOAuthState, OAUTH_STATE_COOKIE,
  encryptOAuth2FAPending, decryptOAuth2FAPending, OAUTH_2FA_COOKIE,
  encryptOAuthPendingRegistration, decryptOAuthPendingRegistration, OAUTH_PENDING_REG_COOKIE,
} from '../lib/oauth.js';
import type { User } from '../database/schema.js';
import {
  FinalizeOAuthRegistrationSchema,
  VerifyOAuth2FASchema,
  RefreshBodySchema,
  LogoutBodySchema,
  OAuthProviderParamsSchema,
  OAuthProviderQuerySchema,
  OAuthCallbackQuerySchema,
  PasskeyAuthVerifySchema,
} from '../database/schemas.js';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

/**
 * Shared 2FA verification logic used by both password login and OAuth 2FA.
 * Verifies TOTP code or recovery code, handles outdated secrets, and manages
 * recovery code consumption + audit logging.
 *
 * @returns void on success, throws AppError on failure
 */
async function verifyTotpOrRecoveryCode(
  user: User & { totp_secret?: string | null; recovery_codes?: string | null },
  totpCode: string,
  request: FastifyRequest,
  method: string, // e.g. 'password', 'oauth_google'
): Promise<void> {
  const otp = new OTP({ strategy: 'totp' });

  // Check if secret is missing or too short (migration from otplib v12 to v13)
  if (!user.totp_secret || user.totp_secret.length < 16) {
    const reason = !user.totp_secret ? '2FA secret decryption failed' : '2FA secret too short';
    request.log.warn({ userId: user.id, reason }, 'Disabling 2FA');
    await store.users.update(user.id, {
      totp_enabled: false,
      totp_secret_encrypted: null,
      recovery_codes_encrypted: null,
    });
    throw new AppError(
      400,
      'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
      'TOTP_SECRET_OUTDATED',
    );
  }

  let isValidTotp = false;
  try {
    const result = await otp.verify({
      token: totpCode,
      secret: user.totp_secret,
      epochTolerance: 1, // ±30s tolerance for clock drift
    });
    isValidTotp = result.valid;
  } catch (error: unknown) {
    if (error instanceof Error && error.name === 'SecretTooShortError') {
      request.log.warn({ userId: user.id }, '2FA secret validation failed, disabling 2FA');
      await store.users.update(user.id, {
        totp_enabled: false,
        totp_secret_encrypted: null,
        recovery_codes_encrypted: null,
      });
      throw new AppError(
        400,
        'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
        'TOTP_SECRET_OUTDATED',
      );
    }
    request.log.warn({ error, userId: user.id }, 'TOTP verification error, treating as invalid code');
    isValidTotp = false;
  }

  // If invalid, try recovery codes
  if (!isValidTotp) {
    let recoveryCodes: string[] = [];
    if (user.recovery_codes) {
      try {
        recoveryCodes = JSON.parse(user.recovery_codes) as string[];
      } catch {
        request.log.error({ userId: user.id }, 'Corrupted recovery codes JSON — treating as empty');
      }
    }

    // Use constant-time comparison to prevent timing attacks
    let codeIndex = -1;
    for (let i = 0; i < recoveryCodes.length; i++) {
      const code = recoveryCodes[i];
      if (code && code.length === totpCode.length) {
        try {
          const a = Buffer.from(code, 'utf8');
          const b = Buffer.from(totpCode, 'utf8');
          if (crypto.timingSafeEqual(a, b)) {
            codeIndex = i;
            break;
          }
        } catch {
          // Continue if lengths don't match exactly
        }
      }
    }

    if (codeIndex === -1) {
      // Audit log for failed 2FA
      const reason = totpCode.length === 8 ? 'invalid_2fa_backup_code' : 'invalid_2fa_code';
      await store.audit.createLog(
        user.id,
        'login_failed',
        JSON.stringify({ reason, method }),
        getClientIp(request),
        request.headers['user-agent'],
      );
      throw new AppError(
        401,
        totpCode.length === 8 ? 'Backup code is incorrect' : '2FA code is incorrect',
        'INVALID_2FA_CODE',
      );
    }

    // Remove used recovery code
    recoveryCodes.splice(codeIndex, 1);
    await store.users.update(user.id, {
      recovery_codes: JSON.stringify(recoveryCodes),
    });

    await store.audit.createLog(
      user.id,
      '2fa_recovery_code_used',
      JSON.stringify({ remaining_codes: recoveryCodes.length, method }),
      getClientIp(request),
      request.headers['user-agent'],
    );
  }
}

/**
 * Authentication routes
 */
export default async function authRoutes(fastify: FastifyInstance) {

  // Stricter rate limiting for auth endpoints (anti-brute force)
  const authRateLimitConfig = {
    max: 5,
    timeWindow: '1 minute',
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: 'Too many attempts',
      message: 'Too many authentication attempts. Please try again in 1 minute.',
    }),
  };

  const setAuthCookies = (reply: FastifyReply, accessToken: { token: string; expiresAt: number }, refreshToken: { token: string; expiresAt: number }) => {
    reply.setCookie(ACCESS_COOKIE, accessToken.token, baseCookieOptions(accessToken.expiresAt));
    reply.setCookie(REFRESH_COOKIE, refreshToken.token, baseCookieOptions(refreshToken.expiresAt));
  };

  /**
   * Register new user
   */
  fastify.post('/register', {
    config: {
      rateLimit: authRateLimitConfig,
    },
    schema: {
      description: 'Register a new user account',
      tags: ['Authentication'],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['username', 'email', 'password', 'tos_accepted'],
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 20 },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8, maxLength: 128 },
          tos_accepted: { type: 'boolean' },
        },
      },
      response: {
        201: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            data: {
              type: 'object',
              properties: {
                pending_approval: { type: 'boolean' },
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
  }, async (request, reply) => {
    try {
      // Validate with Zod (regex patterns not checked by Fastify)
      const userData = validateWithZod(UserRegistrationSchema, request.body);
      
      // Check if user already exists (return generic error to prevent account enumeration)
      const existingUser = await store.users.findByEmail(userData.email);
      if (existingUser) {
        throw new AppError(409, 'Unable to create account with these credentials', 'REGISTRATION_FAILED');
      }

      // Check if email is already used as an OAuth provider email by another user
      const oauthWithEmail = await store.oauth.findByProviderEmail(userData.email);
      if (oauthWithEmail) {
        throw new AppError(409, 'Unable to create account with these credentials', 'REGISTRATION_FAILED');
      }

      // Check if email is banned
      if (await store.isEmailBanned(userData.email)) {
        throw new AppError(403, 'This email address is not allowed', 'EMAIL_BANNED');
      }

      // Check if username is taken
      const existingUsername = await store.users.findByUsername(userData.username);
      if (existingUsername) {
        throw new AppError(409, 'This username is already taken', 'USERNAME_TAKEN');
      }

      // Hash password
      const passwordHash = await AuthService.hashPassword(userData.password);

      // Create user
      const user = await store.users.create({
        username: userData.username,
        email: userData.email,
        password_hash: passwordHash,
      });

      // Record ToS acceptance timestamp via repository
      await store.users.acceptTos(user.id);

      // Check if user is approved
      if (!user.is_approved) {
        // User created but needs approval - don't return token or user data
        return reply.status(201).send({
          success: true,
          message: 'Registration successful. Your account is awaiting admin approval.',
          data: {
            pending_approval: true,
          },
        });
      }

      // Generate tokens (only for approved users)
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      await store.auth.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);

      setAuthCookies(reply, accessToken, refreshToken);

      return reply.status(201).send({
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
      return handleRouteError(error, request, reply, 'User registration');
    }
  });

  /**
   * Login user
   */
  fastify.post('/login', {
    config: {
      rateLimit: authRateLimitConfig,
    },
    schema: {
      description: 'Login with email and password',
      tags: ['Authentication'],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 1, maxLength: 128 },
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
                requires_2fa: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      // Validate with Zod
      const loginData = validateWithZod(UserLoginSchema, request.body);
      
      // Find user by email - decrypt 2FA secrets for verification
      const user = await store.users.findByEmail(loginData.email, true);
      
      // SECURITY: Always execute bcrypt to prevent timing attacks
      // If user doesn't exist, use a pre-computed hash to make response time consistent
      // This prevents attackers from determining if an email exists by measuring response time
      const FAKE_HASH = '$2b$12$Xx8WdVd0fm4kDWJVIYfQc.6ELKfyntZj5F97ILy/yzfDyoZAb8Reu';

      // Check for OAuth-only accounts (no password set)
      if (user && !user.password_hash) {
        // Still run bcrypt to prevent timing attacks
        await AuthService.verifyPassword(loginData.password, FAKE_HASH);

        const oauthAccounts = await store.oauth.findByUserId(user.id);
        const providerNames = oauthAccounts.map(a => a.provider);
        throw new AppError(
          401,
          `This account uses social login. Please sign in with ${providerNames.join(' or ')}.`,
          'OAUTH_ONLY_ACCOUNT',
        );
      }

      const hashToCompare = user?.password_hash || FAKE_HASH;
      
      // Verify password (always executed to prevent timing attacks)
      const isValidPassword = await AuthService.verifyPassword(
        loginData.password,
        hashToCompare
      );

      // Check credentials - user must exist AND password must be valid
      if (!user || !isValidPassword) {
        // Audit log for failed login (only if user exists to avoid FK constraint error)
        if (user) {
          await store.audit.createLog(
            user.id,
            'login_failed',
            JSON.stringify({ reason: 'invalid_password' }),
            getClientIp(request),
            request.headers['user-agent']
          );
        }
        throw new AppError(401, 'Email or password is incorrect', 'INVALID_CREDENTIALS');
      }

      // Check if user is approved
      if (!user.is_approved) {
        throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');
      }

      // Check moderation status
      const loginRestriction = await enforceRestriction(user);
      if (loginRestriction.result === 'blocked') {
        await store.audit.createLog(user.id, 'login_failed', JSON.stringify({ reason: 'account_restricted', restriction_type: user.restriction_type }), getClientIp(request), request.headers['user-agent']);
        throw new AppError(403, loginRestriction.errorMessage, 'ACCOUNT_RESTRICTED',
          loginRestriction.expiresAt ? { restriction_expires_at: loginRestriction.expiresAt } : undefined);
      }

      // Check if 2FA is enabled
      if (user.totp_enabled) {
        const { totp_code } = loginData;

        // If no code provided, return requires_2fa flag
        if (!totp_code) {
          return reply.status(200).send({
            success: true,
            data: {
              requires_2fa: true,
            },
          });
        }

        // Verify TOTP code or recovery code (shared logic)
        await verifyTotpOrRecoveryCode(user, totp_code, request, 'password');
      }

      // Generate tokens
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      await store.auth.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
      setAuthCookies(reply, accessToken, refreshToken);

      // Audit log for successful login
      await store.audit.createLog(
        user.id,
        'login_success',
        JSON.stringify({ method: user.totp_enabled ? '2fa' : 'password' }),
        getClientIp(request),
        request.headers['user-agent']
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
          requires_2fa: false,
        },
      });

    } catch (error) {
      return handleRouteError(error, request, reply, 'User login');
    }
  });

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
        request.log.warn({ cookies: request.cookies }, 'Refresh token missing');
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

  // ==================== OAuth routes ====================

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
    } catch { /* not logged in — normal login flow */ }

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
          // Already linked → verify user
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
            // Account exists but OAuth is not linked → user must log in and link manually
            // This is the industry-standard approach (GitHub, GitLab, Stripe, etc.)
            // to prevent account takeover via email matching.
            return fail('oauth_email_taken');
          } else {
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

  // ==================== Finalize OAuth Registration ====================

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

  // ==================== Verify OAuth 2FA ====================

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

  // ==================== Passkey Authentication ====================

  const PASSKEY_CHALLENGE_TTL = 5 * 60 * 1000;

  const rpID = appConfig.WEBAUTHN_RP_ID;
  const rpOrigin = appConfig.WEBAUTHN_RP_ORIGIN;

  /**
   * POST /api/auth/passkey/authenticate-options - Generate authentication options (no auth required)
   */
  fastify.post('/passkey/authenticate-options', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Generate WebAuthn authentication options',
      tags: ['Authentication'],
    },
  }, async (request, reply) => {
    try {
      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: 'preferred',
      });

      // Use a random key since the user is not yet identified
      const challengeKey = crypto.randomBytes(16).toString('hex');
      await store.challenges.store(`passkey_authn:${challengeKey}`, 'passkey_authn', options.challenge, PASSKEY_CHALLENGE_TTL);

      return reply.status(200).send({
        success: true,
        data: {
          ...options,
          challengeKey,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey authenticate options');
    }
  });

  /**
   * POST /api/auth/passkey/authenticate-verify - Verify authentication response (no auth required)
   */
  fastify.post('/passkey/authenticate-verify', {
    config: { rateLimit: authRateLimitConfig },
    schema: {
      description: 'Verify WebAuthn authentication',
      tags: ['Authentication'],
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          credential: { type: 'object', maxProperties: 20 },
          challengeKey: { type: 'string' },
        },
        required: ['credential', 'challengeKey'],
      },
    },
  }, async (request, reply) => {
    try {
      const { credential, challengeKey } = validateWithZod(PasskeyAuthVerifySchema, request.body);

      const challengeValue = await store.challenges.consume(`passkey_authn:${challengeKey}`);
      if (!challengeValue) {
        throw new AppError(400, 'Authentication challenge expired. Please try again.', 'CHALLENGE_EXPIRED');
      }

      // Extract credential ID from the response to find the passkey
      const cred = credential as { id?: string; rawId?: string; response?: unknown };
      if (!cred.id) throw new AppError(400, 'Missing credential ID', 'INVALID_CREDENTIAL');

      const passkey = await store.passkeys.findByCredentialId(cred.id);
      if (!passkey) {
        // Don't reveal whether the credential exists — use generic message
        throw new AppError(401, 'Authentication failed', 'AUTH_FAILED');
      }

      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: credential as unknown as Parameters<typeof verifyAuthenticationResponse>[0]['response'],
          expectedChallenge: challengeValue,
          expectedOrigin: rpOrigin,
          expectedRPID: rpID,
          credential: {
            id: passkey.credential_id,
            publicKey: new Uint8Array(Buffer.from(passkey.public_key, 'base64url')),
            counter: passkey.counter,
            transports: passkey.transports ? (JSON.parse(passkey.transports) as AuthenticatorTransportFuture[]) : undefined,
          },
          requireUserVerification: false,
        });
      } catch (verifyErr) {
        request.log.error({ err: verifyErr }, 'verifyAuthenticationResponse failed');
        throw new AppError(401, 'Authentication failed', 'VERIFICATION_FAILED');
      }

      if (!verification.verified) {
        throw new AppError(401, 'Authentication failed', 'VERIFICATION_FAILED');
      }

      // Update counter
      await store.passkeys.updateCounter(passkey.credential_id, verification.authenticationInfo.newCounter);

      // Look up the user
      const user = await store.users.findById(passkey.user_id);
      if (!user) throw new AppError(401, 'Authentication failed', 'AUTH_FAILED');
      if (!user.is_approved) throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');

      // Check moderation status (same logic as password login)
      const passkeyRestriction = await enforceRestriction(user);
      if (passkeyRestriction.result === 'blocked') {
        await store.audit.createLog(user.id, 'login_failed', JSON.stringify({ reason: 'account_restricted', method: 'passkey', restriction_type: user.restriction_type }), getClientIp(request), request.headers['user-agent']);
        throw new AppError(403, passkeyRestriction.errorMessage, 'ACCOUNT_RESTRICTED',
          passkeyRestriction.expiresAt ? { restriction_expires_at: passkeyRestriction.expiresAt } : undefined);
      }

      // Generate tokens and set cookies
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      await store.auth.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt, getClientIp(request), request.headers['user-agent'], accessToken.jti);
      setAuthCookies(reply, accessToken, refreshToken);

      // Audit log
      await store.audit.createLog(
        user.id,
        'login_success',
        JSON.stringify({ method: 'passkey', passkey_id: passkey.id }),
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
          token_expires_at: accessToken.expiresAt,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Passkey authenticate verify');
    }
  });
}

/**
 * Generate a unique username from an OAuth display name.
 * Sanitizes to [a-zA-Z0-9_], truncates to 17 chars, and appends
 * a random suffix if the name is already taken.
 */
async function generateUniqueUsername(displayName: string): Promise<string> {
  // Sanitize: keep only allowed characters
  let base = displayName.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 17);
  if (base.length < 3) base = 'user';

  // Try the base name first
  const existing = await store.users.findByUsername(base);
  if (!existing) return base;

  // Append random suffix
  for (let i = 0; i < 10; i++) {
    const suffix = crypto.randomInt(100, 999).toString();
    const candidate = `${base.slice(0, 17)}_${suffix}`;
    const taken = await store.users.findByUsername(candidate);
    if (!taken) return candidate;
  }

  // Fallback: fully random
  return `user_${crypto.randomBytes(4).toString('hex')}`;
}