import { FastifyInstance } from 'fastify';
import { AuthService, UserRegistrationSchema, UserLoginSchema } from '../lib/auth.js';
import { getStore } from '../lib/store.js';

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

      // Generate token
      const token = AuthService.generateToken(user.id);

      request.log.info({ userId: user.id }, 'New user registered');

      return reply.status(201).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
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
      const loginData = UserLoginSchema.parse(request.body);
      
      // Find user by email
      const user = await store.getUserByEmail(loginData.email);
      if (!user) {
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
        return reply.status(401).send({
          success: false,
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
        });
      }

      // Generate token
      const token = AuthService.generateToken(user.id!);

      request.log.info({ userId: user.id }, 'User logged in');

      return reply.status(200).send({
        success: true,
        data: {
          id: user.id!,
          username: user.username,
          email: user.email,
          avatar_url: AuthService.getGravatarUrl(user.email),
          token,
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
        created_at: user.created_at!,
      },
    });
  });
}