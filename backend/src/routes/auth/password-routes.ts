import type { FastifyInstance } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../../lib/auth.js';
import { store } from '../../database/index.js';
import { getClientIp, enforceRestriction } from '../../lib/middleware.js';
import { appConfig } from '../../lib/config.js';
import { validateWithZod, handleRouteError } from '../../lib/validation-handler.js';
import { AppError } from '../../lib/errors.js';
import { verifyTotpOrRecoveryCode } from '../../lib/two-factor.js';
import type { AuthRoutesContext } from './shared.js';

export function registerPasswordAuthRoutes(
  fastify: FastifyInstance,
  { authRateLimitConfig, setAuthCookies }: AuthRoutesContext,
): void {
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
}
