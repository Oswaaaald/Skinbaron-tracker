import { FastifyInstance, FastifyReply } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { getStore } from '../lib/store.js';
import { getClientIp, ACCESS_COOKIE, REFRESH_COOKIE } from '../lib/middleware.js';
import { appConfig } from '../lib/config.js';
import { validateWithZod, handleRouteError } from '../lib/validation-handler.js';
import { AppError } from '../lib/errors.js';
import { OTP } from 'otplib';
import crypto from 'crypto';

// 2FA attempt tracking
type TwoFAAttempt = {
  attempts: number;
  lockedUntil?: number;
};

const twoFAAttempts = new Map<number, TwoFAAttempt>();
const MAX_2FA_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

function record2FAFailure(userId: number): boolean {
  const now = Date.now();
  const record = twoFAAttempts.get(userId);
  
  if (record?.lockedUntil && record.lockedUntil > now) {
    return false; // Still locked
  }
  
  const attempts = (record?.attempts || 0) + 1;
  
  if (attempts >= MAX_2FA_ATTEMPTS) {
    twoFAAttempts.set(userId, {
      attempts,
      lockedUntil: now + LOCKOUT_DURATION_MS
    });
    return false; // Now locked
  }
  
  twoFAAttempts.set(userId, { attempts });
  return true; // Not locked yet
}

function reset2FAAttempts(userId: number): void {
  twoFAAttempts.delete(userId);
}

function is2FALocked(userId: number): { locked: boolean; remainingTime?: number } {
  const record = twoFAAttempts.get(userId);
  if (!record?.lockedUntil) return { locked: false };
  
  const now = Date.now();
  if (record.lockedUntil <= now) {
    twoFAAttempts.delete(userId);
    return { locked: false };
  }
  
  return {
    locked: true,
    remainingTime: Math.ceil((record.lockedUntil - now) / 1000)
  };
}

// Cleanup expired locks every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [userId, record] of twoFAAttempts.entries()) {
    if (record.lockedUntil && record.lockedUntil <= now) {
      twoFAAttempts.delete(userId);
    }
  }
}, 5 * 60 * 1000);

// Extend FastifyInstance type
declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

/**
 * Authentication routes
 */
export default async function authRoutes(fastify: FastifyInstance) {
  const store = getStore();

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

  const clearAuthCookies = (reply: FastifyReply) => {
    reply.setCookie(ACCESS_COOKIE, '', { ...cookieOptions(), expires: new Date(0) });
    reply.setCookie(REFRESH_COOKIE, '', { ...cookieOptions(), expires: new Date(0) });
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
                id: { type: 'number' },
                username: { type: 'string' },
                email: { type: 'string' },
                avatar_url: { type: 'string' },
                is_admin: { type: 'boolean' },
                is_super_admin: { type: 'boolean' },
                token_expires_at: { type: 'number' },
                pending_approval: { type: 'boolean' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      // Validate with Zod (regex patterns not checked by Fastify)
      const userData = validateWithZod(UserRegistrationSchema, request.body, 'Registration data');
      
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

      // Check if user is approved
      if (!user.is_approved) {
        // User created but needs approval - don't return token
        return reply.status(201).send({
          success: true,
          message: 'Registration successful. Your account is awaiting admin approval.',
          data: {
            id: user.id!,
            username: user.username,
            email: user.email,
            pending_approval: true,
          },
        });
      }

      // Generate tokens (only for approved users)
      const accessToken = AuthService.generateAccessToken(user.id);
      const refreshToken = AuthService.generateRefreshToken(user.id);
      store.addRefreshToken(user.id!, refreshToken.token, refreshToken.jti, refreshToken.expiresAt);

      setAuthCookies(reply, accessToken, refreshToken);

      return reply.status(201).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: Boolean(user.is_admin),
          is_super_admin: Boolean(user.is_super_admin),
          token_expires_at: accessToken.expiresAt,
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
                token_expires_at: { type: 'number' },
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
      const loginData = validateWithZod(UserLoginSchema, request.body, 'Login data');
      
      // Find user by email
      const user = await store.getUserByEmail(loginData.email);
      if (!user) {
        // Don't create audit log for non-existent emails (would cause FK constraint error)
        throw new AppError(401, 'Email or password is incorrect', 'INVALID_CREDENTIALS');
      }

      // Verify password
      const isValidPassword = await AuthService.verifyPassword(
        loginData.password,
        user.password_hash
      );

      if (!isValidPassword) {
        // Audit log for failed login (wrong password)
        store.createAuditLog(
          user.id!,
          'login_failed',
          JSON.stringify({ reason: 'invalid_password' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        throw new AppError(401, 'Email or password is incorrect', 'INVALID_CREDENTIALS');
      }

      // Check if user is approved
      if (!user.is_approved) {
        throw new AppError(403, 'Your account is awaiting admin approval', 'PENDING_APPROVAL');
      }

      // Check if 2FA is enabled
      if (user.totp_enabled) {
        const { totp_code } = request.body as { totp_code?: string };

        // Check if user is locked out from too many failed 2FA attempts
        const lockStatus = is2FALocked(user.id!);
        if (lockStatus.locked) {
          return reply.status(429).send({
            success: false,
            error: 'Too many failed 2FA attempts',
            message: `Account temporarily locked. Try again in ${lockStatus.remainingTime} seconds`,
            retry_after: lockStatus.remainingTime,
          });
        }

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
        
        // Check if secret is too short (migration from otplib v12 to v13)
        if (user.totp_secret && user.totp_secret.length < 16) {
          request.log.warn({ email: user.email }, '2FA secret too short, disabling 2FA');
          // Disable 2FA for this user
          store.updateUser(user.id, {
            totp_enabled: 0,
            totp_secret_encrypted: null,
            recovery_codes_encrypted: null,
          });
          
          return reply.status(400).send({
            success: false,
            error: 'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
          });
        }
        
        let isValidTotp = false;
        try {
          const result = await otp.verify({
            token: totp_code,
            secret: user.totp_secret!,
            epochTolerance: 1, // ±30s tolerance for clock drift
          });
          isValidTotp = result.valid;
        } catch (error: any) {
          // Handle SecretTooShortError from otplib v13 (legacy secrets)
          if (error?.name === 'SecretTooShortError') {
            request.log.warn({ email: user.email }, '2FA secret validation failed, disabling 2FA');
            store.updateUser(user.id, {
              totp_enabled: 0,
              totp_secret_encrypted: null,
              recovery_codes_encrypted: null,
            });
            
            return reply.status(400).send({
              success: false,
              error: 'Your 2FA configuration is outdated and has been reset. Please set up 2FA again in your profile settings.',
            });
          }
          throw error; // Re-throw other errors
        }

        // If invalid, try recovery codes
        if (!isValidTotp) {
          const recoveryCodes = user.recovery_codes ? JSON.parse(user.recovery_codes) : [];
          
          // Use constant-time comparison to prevent timing attacks
          let codeIndex = -1;
          for (let i = 0; i < recoveryCodes.length; i++) {
            if (recoveryCodes[i].length === totp_code.length) {
              try {
                const a = Buffer.from(recoveryCodes[i], 'utf8');
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
            // Record failed attempt
            const canContinue = record2FAFailure(user.id!);
            
            // Audit log for failed 2FA
            const attemptsRecord = twoFAAttempts.get(user.id!);
            store.createAuditLog(
              user.id!,
              'login_failed',
              JSON.stringify({ 
                reason: 'invalid_2fa_code',
                attempts: attemptsRecord?.attempts || 1,
                locked: !canContinue
              }),
              getClientIp(request),
              request.headers['user-agent']
            );
            
            if (!canContinue) {
              return reply.status(429).send({
                success: false,
                error: 'Too many failed attempts',
                message: 'Account temporarily locked due to multiple failed 2FA attempts. Try again in 15 minutes',
              });
            }
            
            return reply.status(401).send({
              success: false,
              error: 'Invalid 2FA code',
              message: '2FA code is incorrect',
              remaining_attempts: MAX_2FA_ATTEMPTS - (attemptsRecord?.attempts || 1),
            });
          }

          // Remove used recovery code
          recoveryCodes.splice(codeIndex, 1);
          store.updateUser(user.id!, {
            recovery_codes: JSON.stringify(recoveryCodes),
          });

          // Audit log
          store.createAuditLog(
            user.id!,
            '2fa_recovery_code_used',
            JSON.stringify({ remaining_codes: recoveryCodes.length }),
            getClientIp(request),
            request.headers['user-agent']
          );
        }
        
        // Reset failed attempts on successful 2FA
        reset2FAAttempts(user.id!);
      }

      // Generate tokens
      const accessToken = AuthService.generateAccessToken(user.id!);
      const refreshToken = AuthService.generateRefreshToken(user.id!);
      store.addRefreshToken(user.id!, refreshToken.token, refreshToken.jti, refreshToken.expiresAt);
      setAuthCookies(reply, accessToken, refreshToken);

      // Audit log for successful login
      store.createAuditLog(
        user.id!,
        'login_success',
        JSON.stringify({ method: user.totp_enabled ? '2fa' : 'password' }),
        getClientIp(request),
        request.headers['user-agent']
      );

        return reply.status(200).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: Boolean(user.is_admin),
          is_super_admin: Boolean(user.is_super_admin),
          token_expires_at: accessToken.expiresAt,
          requires_2fa: false,
        },
      });

    } catch (error) {
      return handleRouteError(error, request, reply, 'User login');
    }
  });

  fastify.get('/me', {
    schema: {
      description: 'Get current user profile',
      tags: ['Authentication'],
      security: [{ bearerAuth: [] }],
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
                created_at: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      // User is already attached by auth middleware
      if (!request.user) {
        throw new AppError(401, 'Authentication required', 'UNAUTHENTICATED');
      }
      
      const user = await store.getUserById(request.user.id);
      
      if (!user) {
        throw new AppError(404, 'User not found', 'USER_NOT_FOUND');
      }
      
      return reply.status(200).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: Boolean(user.is_admin),
          is_super_admin: Boolean(user.is_super_admin),
          created_at: user.created_at!,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get current user');
    }
  });

  fastify.post('/refresh', {
    schema: {
      description: 'Refresh access token using a valid refresh token',
      tags: ['Authentication'],
      body: {
        anyOf: [
          { type: 'null' },
          {
            type: 'object',
            properties: {
              refresh_token: { type: 'string' },
            },
          },
        ],
      },
    },
  }, async (request, reply) => {
    try {
      const { refresh_token: refreshFromBody } = (request.body as { refresh_token?: string } | null) || {};
      const refresh_token = refreshFromBody || (request.cookies?.[REFRESH_COOKIE] as string | undefined);

      if (!refresh_token) {
        request.log.warn({ cookies: request.cookies }, 'Refresh token missing');
        throw new AppError(400, 'Refresh token required', 'REFRESH_TOKEN_MISSING');
      }

      const payload = AuthService.verifyToken(refresh_token, 'refresh');
      if (!payload || !payload.jti) {
        request.log.warn({ hasToken: !!refresh_token }, 'Invalid refresh token signature');
        throw new AppError(401, 'Invalid refresh token', 'INVALID_REFRESH_TOKEN');
      }

      const tokenRecord = store.getRefreshToken(refresh_token);
      const isExpired = tokenRecord ? new Date(tokenRecord.expires_at).getTime() <= Date.now() : true;
      if (!tokenRecord || tokenRecord.revoked_at || isExpired) {
        request.log.warn({ 
          hasRecord: !!tokenRecord, 
          isRevoked: tokenRecord?.revoked_at ? true : false,
          isExpired,
          jti: payload.jti 
        }, 'Refresh token expired or revoked');
        throw new AppError(401, 'Refresh token expired or revoked', 'REFRESH_TOKEN_EXPIRED');
      }

      // Rotate refresh token
      const newAccess = AuthService.generateAccessToken(payload.userId);
      const newRefresh = AuthService.generateRefreshToken(payload.userId);

      store.revokeRefreshToken(refresh_token, newRefresh.jti);
      store.addRefreshToken(payload.userId, newRefresh.token, newRefresh.jti, newRefresh.expiresAt);
      store.cleanupRefreshTokens();

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
    schema: {
      description: 'Logout user and revoke tokens',
      tags: ['Authentication'],
      body: {
        type: 'object',
        properties: {
          refresh_token: { type: 'string' },
        },
      },
      security: [{ bearerAuth: [] }],
    },
  }, async (request, reply) => {
    try {
      const authHeader = request.headers.authorization;
      const accessToken = AuthService.extractTokenFromHeader(authHeader ?? '') || (request.cookies?.[ACCESS_COOKIE] as string | undefined);
      const { refresh_token: refreshFromBody } = request.body as { refresh_token?: string };
      const refresh_token = refreshFromBody || (request.cookies?.[REFRESH_COOKIE] as string | undefined);

      const accessPayload = accessToken ? AuthService.verifyToken(accessToken, 'access') : null;
      if (accessPayload?.jti) {
        const exp = accessPayload.exp ? accessPayload.exp * 1000 : Date.now();
        store.blacklistAccessToken(accessPayload.jti, accessPayload.userId, exp, 'logout');
      }

      if (refresh_token) {
        store.revokeRefreshToken(refresh_token, 'logout');
      } else if (accessPayload) {
        store.revokeAllRefreshTokensForUser(accessPayload.userId);
      }

      if (accessPayload) {
        store.createAuditLog(
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