import { FastifyInstance, FastifyReply } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { store } from '../database/index.js';
import { getClientIp, ACCESS_COOKIE, REFRESH_COOKIE, clearAuthCookies } from '../lib/middleware.js';
import { appConfig } from '../lib/config.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { OTP } from 'otplib';
import crypto from 'crypto';
import {
  getEnabledProviders, isProviderEnabled,
  createAuthorizationUrl, exchangeCodeForUser,
  encryptOAuthState, decryptOAuthState, OAUTH_STATE_COOKIE,
} from '../lib/oauth.js';

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

  const cookieOptions = (expiresAt?: number) => ({
    httpOnly: true,
    // Cross-subdomain (frontend vs API) needs SameSite=None
    sameSite: appConfig.NODE_ENV === 'production' ? 'none' as const : 'lax' as const,
    path: '/',
    secure: appConfig.NODE_ENV === 'production',
    domain: appConfig.COOKIE_DOMAIN || undefined,
    expires: expiresAt ? new Date(expiresAt) : undefined,
  });

  const setAuthCookies = (reply: FastifyReply, accessToken: { token: string; expiresAt: number }, refreshToken: { token: string; expiresAt: number }) => {
    reply.setCookie(ACCESS_COOKIE, accessToken.token, cookieOptions(accessToken.expiresAt));
    reply.setCookie(REFRESH_COOKIE, refreshToken.token, cookieOptions(refreshToken.expiresAt));
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
        required: ['username', 'email', 'password'],
        properties: {
          username: { type: 'string', minLength: 3, maxLength: 20 },
          email: { type: 'string', format: 'email' },
          password: { type: 'string', minLength: 8 },
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
      
      // Check if user already exists
      const existingUser = await store.getUserByEmail(userData.email);
      if (existingUser) {
        // Check if account is pending approval
        if (!existingUser.is_approved) {
          throw new AppError(409, 'An account with this email is awaiting admin approval. Please wait for approval before attempting to register again.', 'PENDING_APPROVAL');
        }
        
        throw new AppError(409, 'An account with this email already exists', 'USER_EXISTS');
      }

      // Check if username is taken
      const existingUsername = await store.getUserByUsername(userData.username);
      if (existingUsername) {
        throw new AppError(409, 'This username is already taken', 'USERNAME_TAKEN');
      }

      // Hash password
      const passwordHash = await AuthService.hashPassword(userData.password);

      // Create user
      const user = await store.createUser({
        username: userData.username,
        email: userData.email,
        password_hash: passwordHash,
      });

      // Record ToS acceptance timestamp via repository
      await store.acceptTos(user.id);

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
      await store.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt);

      setAuthCookies(reply, accessToken, refreshToken);

      return reply.status(201).send({
        success: true,
        data: {
          id: user.id,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: user.is_admin,
          is_super_admin: user.is_super_admin,
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
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email' },
          password: { type: 'string' },
          totp_code: { type: 'string' },
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
      const user = await store.getUserByEmail(loginData.email, true);
      
      // SECURITY: Always execute bcrypt to prevent timing attacks
      // If user doesn't exist, use a fake hash to make response time consistent
      // This prevents attackers from determining if an email exists by measuring response time
      const FAKE_HASH = '$2b$12$K4DmKg8K0p3vQ8mK1p3vQeK4DmKg8K0p3vQ8mK1p3vQeK4DmKg8K';

      // Check for OAuth-only accounts (no password set)
      if (user && !user.password_hash) {
        // Still run bcrypt to prevent timing attacks
        await AuthService.verifyPassword(loginData.password, FAKE_HASH);

        const oauthAccounts = await store.getOAuthAccountsByUserId(user.id);
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
          await store.createAuditLog(
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

      // Check if 2FA is enabled
      if (user.totp_enabled) {
        const { totp_code } = request.body as { totp_code?: string };

        // If no code provided, return requires_2fa flag
        if (!totp_code) {
          return reply.status(200).send({
            success: true,
            data: {
              requires_2fa: true,
            },
          });
        }

        // Verify TOTP code
        const otp = new OTP({ strategy: 'totp' });
        
        // Check if secret is missing (decryption failed) or too short (migration from otplib v12 to v13)
        if (!user.totp_secret || user.totp_secret.length < 16) {
          const reason = !user.totp_secret ? '2FA secret decryption failed' : '2FA secret too short';
          request.log.warn({ email: user.email, reason }, 'Disabling 2FA');
          // Disable 2FA for this user
          await store.updateUser(user.id, {
            totp_enabled: false,
            totp_secret_encrypted: null,
            recovery_codes_encrypted: null,
          });
          
          throw new AppError(
            400,
            'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
            'TOTP_SECRET_OUTDATED'
          );
        }
        
        let isValidTotp = false;
        try {
          const result = await otp.verify({
            token: totp_code,
            secret: user.totp_secret,
            epochTolerance: 1, // ±30s tolerance for clock drift
          });
          isValidTotp = result.valid;
        } catch (error: unknown) {
          // Handle SecretTooShortError from otplib v13 (legacy secrets)
          if (error instanceof Error && error.name === 'SecretTooShortError') {
            request.log.warn({ email: user.email }, '2FA secret validation failed, disabling 2FA');
            await store.updateUser(user.id, {
              totp_enabled: false,
              totp_secret_encrypted: null,
              recovery_codes_encrypted: null,
            });
            
            throw new AppError(
              400,
              'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
              'TOTP_SECRET_OUTDATED'
            );
          }
          // Log the error and treat as invalid code (prevent 500 errors)
          request.log.warn({ error, email: user.email }, 'TOTP verification error, treating as invalid code');
          isValidTotp = false;
        }

        // If invalid, try recovery codes
        if (!isValidTotp) {
          const recoveryCodes = user.recovery_codes ? JSON.parse(user.recovery_codes) as string[] : [];
          
          // Use constant-time comparison to prevent timing attacks
          let codeIndex = -1;
          for (let i = 0; i < recoveryCodes.length; i++) {
            const code = recoveryCodes[i];
            if (code && code.length === totp_code.length) {
              try {
                const a = Buffer.from(code, 'utf8');
                const b = Buffer.from(totp_code, 'utf8');
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
            const reason = totp_code.length === 8 ? 'invalid_2fa_backup_code' : 'invalid_2fa_code';
            await store.createAuditLog(
              user.id,
              'login_failed',
              JSON.stringify({ reason }),
              getClientIp(request),
              request.headers['user-agent']
            );
            
            const errorMessage = totp_code.length === 8 
              ? 'Backup code is incorrect' 
              : '2FA code is incorrect';
            
            throw new AppError(
              401,
              errorMessage,
              'INVALID_2FA_CODE'
            );
          }

          // Remove used recovery code
          recoveryCodes.splice(codeIndex, 1);
          await store.updateUser(user.id, {
            recovery_codes: JSON.stringify(recoveryCodes),
          });

          // Audit log
          await store.createAuditLog(
            user.id,
            '2fa_recovery_code_used',
            JSON.stringify({ remaining_codes: recoveryCodes.length }),
            getClientIp(request),
            request.headers['user-agent']
          );
        }
      }

      // Generate tokens
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      await store.addRefreshToken(user.id, refreshToken.token, refreshToken.jti, refreshToken.expiresAt);
      setAuthCookies(reply, accessToken, refreshToken);

      // Audit log for successful login
      await store.createAuditLog(
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
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: user.is_admin,
          is_super_admin: user.is_super_admin,
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
        properties: {},
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
      const { refresh_token: refreshFromBody } = (request.body as { refresh_token?: string } | null) || {};
      const refresh_token = refreshFromBody || (request.cookies?.[REFRESH_COOKIE]);

      if (!refresh_token) {
        request.log.warn({ cookies: request.cookies }, 'Refresh token missing');
        throw new AppError(400, 'Refresh token required', 'REFRESH_TOKEN_MISSING');
      }

      const payload = AuthService.verifyToken(refresh_token, 'refresh');
      if (!payload || !payload.jti) {
        request.log.warn({ hasToken: !!refresh_token }, 'Invalid refresh token signature');
        throw new AppError(401, 'Invalid refresh token', 'INVALID_REFRESH_TOKEN');
      }

      const tokenRecord = await store.getRefreshToken(refresh_token);
      const isExpired = tokenRecord ? tokenRecord.expires_at.getTime() <= Date.now() : true;
      if (!tokenRecord || tokenRecord.revoked_at || tokenRecord.replaced_by_jti || isExpired) {
        request.log.warn({ 
          hasRecord: !!tokenRecord, 
          isRevoked: tokenRecord?.revoked_at ? true : false,
          isReplaced: tokenRecord?.replaced_by_jti ? true : false,
          isExpired,
          jti: payload.jti 
        }, 'Refresh token expired, revoked, or replaced');
        throw new AppError(401, 'Refresh token expired or revoked', 'REFRESH_TOKEN_EXPIRED');
      }

      // Rotate refresh token
      const newAccess = AuthService.generateAccessToken(payload.userId);
      const newRefresh = AuthService.generateRefreshToken(payload.userId);

      await store.revokeRefreshToken(refresh_token, newRefresh.jti);
      await store.addRefreshToken(payload.userId, newRefresh.token, newRefresh.jti, newRefresh.expiresAt);
      await store.cleanupRefreshTokens();

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
        properties: {
          refresh_token: { type: 'string' },
        },
      },
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const authHeader = request.headers.authorization;
      const accessToken = AuthService.extractTokenFromHeader(authHeader ?? '') || (request.cookies?.[ACCESS_COOKIE]);
      const { refresh_token: refreshFromBody } = request.body as { refresh_token?: string };
      const refresh_token = refreshFromBody || (request.cookies?.[REFRESH_COOKIE]);

      const accessPayload = accessToken ? AuthService.verifyToken(accessToken, 'access') : null;
      
      // Check if user still exists (may have been deleted)
      const userExists = accessPayload ? (await store.getUserById(accessPayload.userId)) !== null : false;
      
      if (accessPayload?.jti && userExists) {
        const exp = accessPayload.exp ? accessPayload.exp * 1000 : Date.now();
        await store.blacklistAccessToken(accessPayload.jti, accessPayload.userId, exp, 'logout');
      }

      if (refresh_token && userExists) {
        await store.revokeRefreshToken(refresh_token, 'logout');
      } else if (accessPayload && userExists) {
        await store.revokeAllRefreshTokensForUser(accessPayload.userId);
      }

      // Clean up revoked tokens from database
      await store.cleanupRefreshTokens();

      if (accessPayload && userExists) {
        await store.createAuditLog(
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
  fastify.get('/oauth/providers', async (_request, reply) => {
    return reply.send({
      success: true,
      data: { providers: getEnabledProviders() },
    });
  });

  /**
   * Initiate OAuth flow — redirect to provider authorization page
   */
  fastify.get<{ Params: { provider: string } }>('/oauth/:provider', {
    schema: {
      params: {
        type: 'object',
        required: ['provider'],
        properties: { provider: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    const { provider } = request.params;

    if (!isProviderEnabled(provider)) {
      throw new AppError(400, `OAuth provider "${provider}" is not available`, 'INVALID_PROVIDER');
    }

    const { url, state, codeVerifier } = createAuthorizationUrl(provider);

    // Store state + codeVerifier in encrypted HttpOnly cookie
    reply.setCookie(OAUTH_STATE_COOKIE, encryptOAuthState(state, codeVerifier), {
      httpOnly: true,
      sameSite: appConfig.NODE_ENV === 'production' ? 'none' as const : 'lax' as const,
      path: '/',
      secure: appConfig.NODE_ENV === 'production',
      domain: appConfig.COOKIE_DOMAIN || undefined,
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
      schema: {
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
      const { provider } = request.params;
      const { code, state, error: oauthError } = request.query;
      const loginUrl = `${appConfig.CORS_ORIGIN}/login`;

      // Helper to redirect with error and clean the state cookie
      const fail = (reason: string) => {
        reply.clearCookie(OAUTH_STATE_COOKIE, {
          httpOnly: true,
          sameSite: appConfig.NODE_ENV === 'production' ? 'none' as const : 'lax' as const,
          path: '/',
          secure: appConfig.NODE_ENV === 'production',
          domain: appConfig.COOKIE_DOMAIN || undefined,
        });
        return reply.redirect(`${loginUrl}?error=${reason}`);
      };

      // --- Pre-flight checks ---
      if (oauthError) return fail('oauth_denied');
      if (!code || !state) return fail('oauth_missing_params');
      if (!isProviderEnabled(provider)) return fail('invalid_provider');

      // Read and validate encrypted state cookie
      const stateCookie = request.cookies[OAUTH_STATE_COOKIE];
      if (!stateCookie) return fail('oauth_state_missing');

      let storedState: { state: string; codeVerifier: string };
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

      // --- Find or create user ---
      try {
        // 1. Check if this OAuth account is already linked
        const existingOAuth = await store.findOAuthAccount(provider, userInfo.id);
        let userId: number;

        if (existingOAuth) {
          // Already linked → verify user
          const user = await store.getUserById(existingOAuth.user_id);
          if (!user) return fail('oauth_user_not_found');
          if (!user.is_approved) return fail('pending_approval');
          userId = user.id;
        } else {
          // 2. Check if a user with the same verified email exists
          const existingUser = await store.getUserByEmail(userInfo.email);

          if (existingUser) {
            if (!existingUser.is_approved) return fail('pending_approval');
            // Auto-link provider to existing account
            await store.linkOAuthAccount(
              existingUser.id,
              provider,
              userInfo.id,
              userInfo.email,
            );
            userId = existingUser.id;

            await store.createAuditLog(
              existingUser.id,
              'oauth_linked',
              JSON.stringify({ provider, provider_email: userInfo.email }),
              getClientIp(request),
              request.headers['user-agent'],
            );
          } else {
            // 3. Create a new user (auto-approved, no password)
            const username = await generateUniqueUsername(userInfo.name ?? provider);
            const newUser = await store.createUser({ username, email: userInfo.email });

            // Auto-approve OAuth users
            if (!newUser.is_approved) {
              await store.updateUser(newUser.id, { is_approved: true });
            }

            await store.linkOAuthAccount(
              newUser.id,
              provider,
              userInfo.id,
              userInfo.email,
            );
            userId = newUser.id;

            await store.createAuditLog(
              newUser.id,
              'oauth_register',
              JSON.stringify({ provider, provider_email: userInfo.email }),
              getClientIp(request),
              request.headers['user-agent'],
            );
          }
        }

        // --- Issue JWT tokens ---
        const accessToken = AuthService.generateAccessToken(userId);
        const refreshToken = AuthService.generateRefreshToken(userId);
        await store.addRefreshToken(userId, refreshToken.token, refreshToken.jti, refreshToken.expiresAt);
        setAuthCookies(reply, accessToken, refreshToken);

        // Clean state cookie
        reply.clearCookie(OAUTH_STATE_COOKIE, {
          httpOnly: true,
          sameSite: appConfig.NODE_ENV === 'production' ? 'none' as const : 'lax' as const,
          path: '/',
          secure: appConfig.NODE_ENV === 'production',
          domain: appConfig.COOKIE_DOMAIN || undefined,
        });

        await store.createAuditLog(
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
  const existing = await store.getUserByUsername(base);
  if (!existing) return base;

  // Append random suffix
  for (let i = 0; i < 10; i++) {
    const suffix = crypto.randomInt(100, 999).toString();
    const candidate = `${base.slice(0, 17)}_${suffix}`;
    const taken = await store.getUserByUsername(candidate);
    if (!taken) return candidate;
  }

  // Fallback: fully random
  return `user_${crypto.randomBytes(4).toString('hex')}`;
}