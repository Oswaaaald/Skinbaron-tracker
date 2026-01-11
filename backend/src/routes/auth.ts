import { FastifyInstance } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { getStore } from '../lib/store.js';
import { getClientIp } from '../lib/middleware.js';
import { authenticator } from 'otplib';

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

  /**
   * Register new user
   */
  fastify.post('/register', {
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
            data: {
              type: 'object',
              properties: {
                id: { type: 'number' },
                username: { type: 'string' },
                email: { type: 'string' },
                avatar_url: { type: 'string' },
                is_admin: { type: 'boolean' },
                is_super_admin: { type: 'boolean' },
                token: { type: 'string' },
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

      // Generate token (only for approved users)
      const token = AuthService.generateToken(user.id);

      return reply.status(201).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          is_admin: Boolean(user.is_admin),
          is_super_admin: Boolean(user.is_super_admin),
          token,
        },
      });

    } catch (error) {
      request.log.error({ error }, 'Registration failed');
      
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
                token: { type: 'string' },
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
        const { totp_code } = request.body as any;

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
        const isValidTotp = authenticator.verify({
          token: totp_code,
          secret: user.totp_secret!,
        });

        // If invalid, try recovery codes
        if (!isValidTotp) {
          const recoveryCodes = user.recovery_codes ? JSON.parse(user.recovery_codes) : [];
          const codeIndex = recoveryCodes.indexOf(totp_code);

          if (codeIndex === -1) {
            // Audit log for failed 2FA
            store.createAuditLog(
              user.id!,
              'login_failed',
              JSON.stringify({ reason: 'invalid_2fa_code' }),
              getClientIp(request),
              request.headers['user-agent']
            );
            return reply.status(401).send({
              success: false,
              error: 'Invalid 2FA code',
              message: '2FA code is incorrect',
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
      }

      // Generate token
      const token = AuthService.generateToken(user.id!);

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
          token,
          requires_2fa: false,
        },
      });

    } catch (error) {
      request.log.error({ error }, 'Login failed');
      
      return reply.status(500).send({
        success: false,
        error: 'Login failed',
        message: 'Internal server error during login',
      });
    }
  });

  /**
   * Get current user profile (requires auth)
   */
  fastify.get('/me', {
    preHandler: [fastify.authenticate], // We'll add this hook
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
}