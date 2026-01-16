import { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { getStore } from '../lib/store.js';
import { getClientIp, ACCESS_COOKIE, REFRESH_COOKIE } from '../lib/middleware.js';
import { appConfig } from '../lib/config.js';
import { authenticator } from 'otplib';
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
    authenticate: (request: any, reply: any) => Promise<void>;
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
      // Validate input
      const userData = UserRegistrationSchema.parse(request.body);
      
      // Check if user already exists
      const existingUser = await store.getUserByEmail(userData.email);
      if (existingUser) {
        // Check if account is pending approval
        if (!existingUser.is_approved) {
          return reply.status(409).send({
            success: false,
            error: 'Account pending approval',
            message: 'An account with this email is awaiting admin approval. Please wait for approval before attempting to register again.',
          });
        }
        
        return reply.status(409).send({
          success: false,
          error: 'User already exists',
          message: 'An account with this email already exists',
        });
      }

      // Check if username is taken
      const existingUsername = await store.getUserByUsername(userData.username);
      if (existingUsername) {
        return reply.status(409).send({
          success: false,
          error: 'Username taken',
          message: 'This username is already taken',
        });
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
      request.log.error({ error }, 'Registration failed');
      
      // Handle Zod validation errors
      if (error && typeof error === 'object' && 'issues' in error) {
        const zodError = error as z.ZodError;
        const firstIssue = zodError.issues?.[0];
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          message: firstIssue?.message || 'Invalid input data',
        });
      }
      
      if (error instanceof Error && error.message.includes('validation')) {
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          message: error.message,
        });
      }

      return reply.status(500).send({
        success: false,
        error: 'Registration failed',
        message: 'Internal server error during registration',
      });
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
      // Validate input
      const loginData = UserLoginSchema.parse(request.body);
      
      // Find user by email
      const user = await store.getUserByEmail(loginData.email);
      if (!user) {
        // Audit log for failed login attempt
        store.createAuditLog(
          0, // No user ID for unknown email
          'login_failed',
          JSON.stringify({ email: loginData.email, reason: 'unknown_email' }),
          getClientIp(request),
          request.headers['user-agent']
        );
        return reply.status(401).send({
          success: false,
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
        });
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
        return reply.status(401).send({
          success: false,
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
        });
      }

      // Check if user is approved
      if (!user.is_approved) {
        return reply.status(403).send({
          success: false,
          error: 'Account pending approval',
          message: 'Your account is awaiting admin approval',
        });
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
        authenticator.options = { window: 1 }; // ±30s tolerance for clock drift
        const isValidTotp = authenticator.verify({
          token: totp_code,
          secret: user.totp_secret!,
        });

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
      request.log.error({ error }, 'Registration failed');
      
      // Handle Zod validation errors
      if (error && typeof error === 'object' && 'issues' in error) {
        const zodError = error as z.ZodError;
        const firstIssue = zodError.issues?.[0];
        return reply.status(400).send({
          success: false,
          error: 'Validation error',
          message: firstIssue?.message || 'Invalid input data',
        });
      }
      
      if (error instanceof Error) {
        // Surface unique constraint violations clearly (email/username already used)
        if (error.message.includes('SQLITE_CONSTRAINT')) {
          const isEmailConflict = error.message.includes('users.email');
          const isUsernameConflict = error.message.includes('users.username');
          return reply.status(409).send({
            success: false,
            error: 'Conflict',
            message: isEmailConflict
              ? 'An account with this email already exists'
              : isUsernameConflict
                ? 'This username is already taken'
                : 'Account already exists',
          });
        }
        
        if (error.message.includes('validation')) {
          return reply.status(400).send({
            success: false,
            error: 'Validation error',
            message: error.message,
          });
        }
      }
      
      // Fallback error response
      return reply.status(500).send({
        success: false,
        error: 'Registration failed',
        message: 'An unexpected error occurred during registration'
      });
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
    // User is already attached by auth middleware
    if (!request.user) {
      return reply.status(401).send({
        success: false,
        error: 'Authentication required',
      });
    }
    
    const user = await store.getUserById(request.user.id);
    
    if (!user) {
      return reply.status(404).send({
        success: false,
        error: 'User not found',
      });
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
    const { refresh_token: refreshFromBody } = (request.body as { refresh_token?: string } | null) || {};
    const refresh_token = refreshFromBody || (request.cookies?.[REFRESH_COOKIE] as string | undefined);

    if (!refresh_token) {
      request.log.warn({ cookies: request.cookies }, 'Refresh token missing');
      return reply.status(400).send({ success: false, error: 'Refresh token required' });
    }

    const payload = AuthService.verifyToken(refresh_token, 'refresh');
    if (!payload || !payload.jti) {
      request.log.warn({ hasToken: !!refresh_token }, 'Invalid refresh token signature');
      return reply.status(401).send({ success: false, error: 'Invalid refresh token' });
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
      return reply.status(401).send({ success: false, error: 'Refresh token expired or revoked' });
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
  });
}