import { initSentry, captureException, flushSentry } from './lib/sentry.js';

// Initialize Sentry BEFORE anything else
initSentry();

import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { appConfig, MAX_UPLOAD_SIZE } from './lib/config.js';
import { ACCESS_COOKIE, baseCookieOptions } from './lib/middleware.js';
import { OAUTH_STATE_COOKIE } from './lib/oauth.js';
import { store } from './database/index.js';
import { closeDatabase, checkDatabaseHealth, initializeDatabase } from './database/connection.js';
import { getSkinBaronClient } from './lib/sbclient.js';
import { getNotificationService } from './lib/notifier.js';
import { getScheduler, type AlertScheduler } from './lib/scheduler.js';
import { handleRouteError } from './lib/validation-handler.js';
import { generateCsrfToken, setCsrfCookie, csrfProtection } from './lib/csrf.js';
import { initOAuthProviders } from './lib/oauth.js';
import rulesRoutes from './routes/rules.js';
import alertsRoutes from './routes/alerts.js';

// Create Fastify instance
const fastify = Fastify({
  logger: {
    level: appConfig.LOG_LEVEL,
  },
  // Trust only the first proxy hop (e.g. nginx/Traefik directly in front of the app)
  trustProxy: 1,
  // Custom error formatter for validation errors (makes them user-friendly)
  schemaErrorFormatter: (errors) => {
    const error = errors[0];
    if (!error) return new Error('Validation failed');
    
    // Extract field name from path, removing "body/" prefix
    let field = error.instancePath.replace(/^\//, '').replace(/\//g, '.');
    if (!field && error.keyword === 'required') {
      field = error.params['missingProperty'] as string;
    }
    
    // Generate user-friendly message
    let message = '';
    
    if (error.keyword === 'minLength') {
      message = field 
        ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at least ${Number(error.params['limit'])} characters`
        : `Must be at least ${Number(error.params['limit'])} characters`;
    } else if (error.keyword === 'maxLength') {
      message = field
        ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at most ${Number(error.params['limit'])} characters`
        : `Must be at most ${Number(error.params['limit'])} characters`;
    } else if (error.keyword === 'format' && error.params['format'] === 'email') {
      message = 'Please enter a valid email address';
    } else if (error.keyword === 'format' && error.params['format'] === 'url') {
      message = 'Please enter a valid URL';
    } else if (error.keyword === 'pattern') {
      if (field === 'username') {
        message = 'Username can only contain letters, numbers and underscores';
      } else if (field === 'password') {
        message = 'Password must contain uppercase, lowercase and number';
      } else {
        message = `${field || 'Field'} format is invalid`;
      }
    } else if (error.keyword === 'required') {
      message = `${field.charAt(0).toUpperCase() + field.slice(1)} is required`;
    } else if (error.keyword === 'minimum') {
      message = `${field || 'Field'} must be at least ${Number(error.params['limit'])}`;
    } else if (error.keyword === 'maximum') {
      message = `${field || 'Field'} must be at most ${Number(error.params['limit'])}`;
    } else if (error.keyword === 'enum') {
      const allowedValues = error.params['allowedValues'] as string[] | undefined;
      message = `${field || 'Field'} must be one of: ${allowedValues?.join(', ') || 'allowed values'}`;
    } else if (error.keyword === 'type') {
      message = `${field || 'Field'} must be a ${String(error.params['type'])}`;
    } else {
      message = error.message || 'Validation error';
    }
    
    return new Error(message);
  }
});

// Attach Fastify logger to scheduler for unified logging
getScheduler().setLogger(fastify.log);

// Graceful shutdown function
const gracefulShutdown = async (signal: string) => {
  fastify.log.info(`Received ${signal}, starting graceful shutdown...`);
  
  try {
    // Stop scheduler
    const scheduler = getScheduler();
    scheduler.stop();
    
    // Close database connection pool
    await closeDatabase();
    
    // Close Fastify
    await fastify.close();

    // Flush pending Sentry events
    await flushSentry();
    
    fastify.log.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    fastify.log.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
};

// Setup graceful shutdown handlers
process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => void gracefulShutdown('SIGINT'));

// Error handlers
process.on('uncaughtException', (error) => {
  captureException(error, { context: 'uncaughtException' });
  fastify.log.fatal({ error }, 'Uncaught Exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  captureException(reason, { context: 'unhandledRejection' });
  fastify.log.fatal({ reason }, 'Unhandled Rejection');
  process.exit(1);
});

// Register plugins
async function registerPlugins() {
  // Swagger documentation
  await fastify.register(swagger, {
    openapi: {
      openapi: '3.0.0',
      info: {
        title: 'SkinBaron Tracker API',
        description: 'API for tracking CS2 skin prices and sending alerts via Discord webhooks',
        version: '1.0.0',
      },
      servers: [
        {
          url: `${appConfig.NEXT_PUBLIC_API_URL}/api`,
          description: appConfig.NODE_ENV === 'production' ? 'Production' : 'Development',
        },
      ],
      tags: [
        { name: 'Authentication', description: 'User authentication and session management' },
        { name: 'Rules', description: 'Price tracking rules management' },
        { name: 'Alerts', description: 'Alert history and management' },
        { name: 'Webhooks', description: 'Discord webhook configuration' },
        { name: 'User', description: 'User profile and settings' },
        { name: 'Admin', description: 'Admin-only endpoints' },
        { name: 'System', description: 'System status and health monitoring' },
        { name: 'Items', description: 'SkinBaron item search' },
      ],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
          },
          cookieAuth: {
            type: 'apiKey',
            in: 'cookie',
            name: 'sb_access',
          },
        },
      },
    },
  });

  await fastify.register(swaggerUi, {
    routePrefix: '/docs',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
      filter: true, // Enable filter bar
    },
    staticCSP: true,
    transformStaticCSP: (header) => header,
    transformSpecification: (swaggerObject, request) => {
      // Types for OpenAPI structure
      type OpenAPIOperation = {
        tags?: string[];
        [key: string]: unknown;
      };
      type OpenAPIPathMethods = Record<string, OpenAPIOperation>;
      type OpenAPITag = {
        name: string;
        description?: string;
      };
      
      // Filter routes based on user role
      const isAdmin = request.user?.is_admin || request.user?.is_super_admin;
      
      if (isAdmin) {
        // Admins see everything
        return swaggerObject;
      }
      
      // Non-admins: hide routes tagged as Admin or System
      const hiddenTags = new Set(['Admin', 'System']);
      const filteredPaths: Record<string, OpenAPIPathMethods> = {};
      const usedTags = new Set<string>();
      const paths = (swaggerObject['paths'] || {}) as Record<string, OpenAPIPathMethods>;
      
      for (const [path, methods] of Object.entries(paths)) {
        const methodsObj = methods;
        const filteredMethods: OpenAPIPathMethods = {};
        
        for (const [verb, op] of Object.entries(methodsObj)) {
          const tags: string[] = op.tags || [];
          const hide = tags.some((t) => hiddenTags.has(t));
          if (!hide) {
            filteredMethods[verb] = op;
            tags.forEach((t) => usedTags.add(t));
          }
        }
        
        if (Object.keys(filteredMethods).length > 0) {
          filteredPaths[path] = filteredMethods;
        }
      }
      
      // Filter tags to only show those with visible routes
      const filteredTags = ((swaggerObject['tags'] || []) as OpenAPITag[]).filter((tag: OpenAPITag) => 
        usedTags.has(tag.name)
      );
      
      return {
        ...swaggerObject,
        paths: filteredPaths,
        tags: filteredTags,
      } as typeof swaggerObject;
    },
    uiHooks: {
      onRequest: (request, reply, done) => {
        // Require authentication (any logged-in user)
        const redirectToLogin = () => {
          const accepts = request.headers.accept ?? '';
          if (accepts.includes('text/html')) {
            reply.status(302).redirect(`${appConfig.CORS_ORIGIN}/login?error=docs_auth_required`);
          } else {
            reply.status(401).send({
              success: false,
              error: 'Unauthorized',
              message: 'Authentication required to view API documentation',
            });
          }
        };
        fastify.authenticate(request, reply)
          .then(() => {
            if (!request.user) {
              redirectToLogin();
              return;
            }
            done();
          })
          .catch(() => {
            redirectToLogin();
          });
      },
    },
  });

  await fastify.register(cookie, {
    hook: 'onRequest',
  });

  // Multipart for avatar uploads
  await fastify.register(multipart, {
    limits: {
      fileSize: MAX_UPLOAD_SIZE,
      files: 1,
      fields: 0,
    },
  });

  // Security middleware
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        fontSrc: ["'self'", 'https:', 'data:'],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
        upgradeInsecureRequests: [],
      },
    },
  });

  // CORS
  await fastify.register(cors, {
    origin: (origin, callback) => {
      // Build allowed origins: API URL (for Swagger) + Frontend URL
      const allowedOrigins = [
        appConfig.NEXT_PUBLIC_API_URL, // API's own domain for Swagger UI
        appConfig.CORS_ORIGIN,          // Frontend URL
      ];
      
      // Allow requests without Origin (healthchecks, curl, Postman, server-to-server).
      // These are non-browser requests — CORS doesn't apply to them.
      // CSRF double-submit cookie protects all state-changing mutations.
      if (!origin) {
        callback(null, true);
        return;
      }
      
      // Check if origin is in allowed list
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
  });

  // Rate limiting
  await fastify.register(rateLimit, {
    max: appConfig.RATE_LIMIT_MAX,
    timeWindow: appConfig.RATE_LIMIT_WINDOW,
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true,
    },
    keyGenerator: (request) => {
      // Use request.ip which respects Fastify's trustProxy setting
      return request.ip;
    },
    errorResponseBuilder: (request, context) => ({
      statusCode: 429,
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests on ${request.method} ${request.url}, please try again in ${Math.ceil(context.ttl / 1000)} seconds`,
    }),
  });

  // Modern authentication decorators (2026)
  const { authMiddleware, requireAdmin, requireSuperAdmin } = await import('./lib/middleware.js');
  
  fastify.decorate('authenticate', authMiddleware);
  fastify.decorate('requireAdmin', requireAdmin);
  fastify.decorate('requireSuperAdmin', requireSuperAdmin);

  // Global error handler for AppError (2026 standards)
  fastify.setErrorHandler(async (error, request, reply) => {
    const { AppError } = await import('./lib/errors.js');
    const { handleRouteError } = await import('./lib/validation-handler.js');

    // OAuth browser-navigation routes must ALWAYS redirect — never return JSON
    // Covers: rate limit (429), schema validation (400), AppError, unexpected crashes
    if (
      request.method === 'GET' &&
      request.url.startsWith('/api/auth/oauth/') &&
      !request.url.endsWith('/providers') // exclude the JSON-only providers endpoint
    ) {
      reply.clearCookie(OAUTH_STATE_COOKIE, baseCookieOptions());
      const isLinkFlow = !!request.cookies?.[ACCESS_COOKIE];
      const reason = (error as { statusCode?: number }).statusCode === 429
        ? 'rate_limited'
        : 'oauth_server_error';
      const target = isLinkFlow
        ? `${appConfig.CORS_ORIGIN}/settings?link_error=${reason}`
        : `${appConfig.CORS_ORIGIN}/login?error=${reason}`;
      request.log.error({ err: error, url: request.url }, 'OAuth browser route error — redirecting');
      return reply.redirect(target);
    }

    if (error instanceof AppError) {
      return handleRouteError(error, request, reply, 'Global handler');
    }
    
    // Capture unexpected errors in Sentry before falling through
    captureException(error, { url: request.url, method: request.method });
    throw error;
  });

  // Custom 404 handler — redirect browsers to frontend, JSON for API consumers
  fastify.setNotFoundHandler((request, reply) => {
    const accepts = request.headers.accept ?? '';
    if (request.method === 'GET' && accepts.includes('text/html')) {
      return reply.redirect(`${appConfig.CORS_ORIGIN}/not-found`);
    }
    return reply.status(404).send({
      success: false,
      error: 'Not Found',
      message: `Route ${request.method}:${request.url} not found`,
    });
  });
}

async function buildSystemSnapshot() {
  const scheduler: AlertScheduler = getScheduler();

  // Scheduler health and stats (synchronous / in-memory — always fast)
  let schedulerHealth = 'unhealthy';
  let simplifiedScheduler: Record<string, string | number | boolean | null> = {};
  try {
    const schedulerStats = scheduler.getStats();
    // Scheduler is healthy if running, or if stopped but has no errors
    schedulerHealth = schedulerStats.isRunning ? 'running' : 
                     (schedulerStats.errorCount === 0 ? 'stopped' : 'unhealthy');
    simplifiedScheduler = {
      isRunning: schedulerStats.isRunning,
      lastRunTime: schedulerStats.lastRunTime ? schedulerStats.lastRunTime.toISOString() : null,
      nextRunTime: schedulerStats.nextRunTime ? schedulerStats.nextRunTime.toISOString() : null,
      totalRuns: schedulerStats.totalRuns,
      totalAlerts: schedulerStats.totalAlerts,
      errorCount: schedulerStats.errorCount,
      lastError: schedulerStats.lastError,
    };
  } catch (error) {
    fastify.log.error({ error }, 'Scheduler stats retrieval failed');
    schedulerHealth = 'unhealthy';
  }

  // Run DB + SkinBaron health checks in parallel (both are I/O-bound)
  const [dbHealth, skinbaronHealth] = await Promise.all([
    checkDatabaseHealth()
      .then(ok => ok ? 'healthy' : 'unhealthy')
      .catch(error => {
        fastify.log.error({ error }, 'Database health check failed');
        return 'unhealthy';
      }),
    getSkinBaronClient().testConnection()
      .then(ok => ok ? 'healthy' : 'unhealthy')
      .catch(error => {
        fastify.log.error({ error }, 'SkinBaron API health check failed');
        return 'unhealthy';
      }),
  ]);

  const services = {
    database: dbHealth,
    skinbaron_api: skinbaronHealth,
    scheduler: schedulerHealth,
  } as const;

  const isHealthy = (service: string, status: string) => {
    if (service === 'scheduler') return status === 'running' || status === 'healthy';
    return status === 'healthy';
  };

  const allServicesHealthy = Object.entries(services).every(([service, status]) =>
    isHealthy(service, status)
  );

  const health = {
    status: allServicesHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    services,
    stats: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: appConfig.APP_VERSION,
    },
  };

  return { health, scheduler: simplifiedScheduler };
}

// Health check endpoint - lightweight, no external dependencies
function setupHealthCheck() {
  fastify.get('/api/health', {
    logLevel: 'warn',
    schema: {
      description: 'Health check endpoint',
      tags: ['System'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            status: { type: 'string' },
            database: { type: 'string' },
            uptime: { type: 'number' },
          },
        },
      },
    },
  }, async (request, reply) => {
    request.log.debug('Health check requested');
    // Lightweight health check - only check database, not external APIs
    let dbHealth = 'healthy';
    try {
      await store.audit.getGlobalStats();
    } catch {
      dbHealth = 'unhealthy';
    }

    const uptime = process.uptime();
    const status = dbHealth === 'healthy' ? 'healthy' : 'degraded';

    return reply.status(200).send({ 
      success: true, 
      status,
      database: dbHealth,
      uptime,
    });
  });
}

// System status endpoint - now includes health snapshot
function setupSystemStatus() {
  fastify.get('/api/system/status', {
    schema: {
      description: 'Get system status including scheduler and health information',
      tags: ['System'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      // Note: No response schema to allow dynamic nested object structure
    },
    preHandler: [fastify.authenticate, fastify.requireAdmin],
  }, async (request, reply) => {
    try {
      const snapshot = await buildSystemSnapshot();
      fastify.log.debug({ snapshot }, 'System status snapshot');
      return reply.status(200).send({
        success: true,
        data: {
          scheduler: snapshot.scheduler,
          health: snapshot.health,
        },
      });
    } catch (error) {
      fastify.log.error({ error }, 'Failed to build system snapshot');
      return handleRouteError(error, request, reply, 'Get system status');
    }
  });
}

// CSRF token endpoint
function setupCsrfEndpoint() {
  fastify.get('/api/csrf-token', {
    schema: {
      description: 'Get a CSRF token for client-side requests',
      tags: ['Authentication'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                csrf_token: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    request.log.debug('CSRF token requested');
    const token = generateCsrfToken();
    setCsrfCookie(reply, token, appConfig.NODE_ENV === 'production');
    
    return reply.status(200).send({
      success: true,
      data: {
        csrf_token: token,
      },
    });
  });
}




// Register API routes
async function registerRoutes() {
  // Public avatar serving route (no auth required, aggressive caching)
  const { readAvatarFile } = await import('./lib/avatar.js');
  fastify.get('/api/avatars/:filename', {
    schema: {
      description: 'Serve user avatar images',
      tags: ['System'],
      params: {
        type: 'object',
        required: ['filename'],
        properties: {
          filename: { type: 'string', pattern: '^[a-f0-9]{32}\\.webp$' },
        },
      },
    },
  }, async (request, reply) => {
    const { filename } = request.params as { filename: string };
    const data = await readAvatarFile(filename);
    if (!data) {
      return reply.status(404).send({ success: false, error: 'Not found' });
    }
    return reply
      .header('Content-Type', 'image/webp')
      .header('Cache-Control', 'public, max-age=86400, immutable')
      .header('X-Content-Type-Options', 'nosniff')
      .header('Cross-Origin-Resource-Policy', 'cross-origin')
      .header('Content-Security-Policy', "default-src 'none'; img-src 'self'")
      .send(data);
  });

  // Import auth routes
  const { default: authRoutes } = await import('./routes/auth.js');
  const { default: webhooksRoutes } = await import('./routes/webhooks.js');
  const { default: itemsRoutes } = await import('./routes/items.js');
  const { default: userRoutes } = await import('./routes/user.js');
  
  // Authentication
  await fastify.register(authRoutes, { prefix: '/api/auth' });
  
  // User profile management
  await fastify.register(userRoutes, { prefix: '/api/user' });
  
  // User webhooks management
  await fastify.register(webhooksRoutes, { prefix: '/api/webhooks' });
  
  // Rules CRUD
  await fastify.register(rulesRoutes, { prefix: '/api/rules' });
  await fastify.register(alertsRoutes, { prefix: '/api/alerts' });
  
  // Items search for autocomplete
  await fastify.register(itemsRoutes, { prefix: '/api/items' });
  
  // Admin routes (requires admin privileges)
  const { default: adminRoutes } = await import('./routes/admin.js');
  await fastify.register(adminRoutes, { prefix: '/api/admin' });
}

// Initialize application
async function initializeApp() {
  try {
    fastify.log.info('🚀 Initializing SkinBaron Tracker API...');

    // Initialize core services
    fastify.log.info('📊 Initializing database...');
    await initializeDatabase();
    fastify.log.info('✅ Database migrations applied');

    // Ensure avatar upload directory exists
    const { ensureUploadDir } = await import('./lib/avatar.js');
    await ensureUploadDir();
    fastify.log.info('✅ Avatar upload directory ready');
    
    fastify.log.info('🔍 Initializing SkinBaron client...');
    getSkinBaronClient();
    
    fastify.log.info('🔔 Initializing notification service...');
    getNotificationService();
    
    fastify.log.info('⏰ Initializing scheduler...');
    const scheduler = getScheduler();

    // Initialize OAuth providers (from env vars)
    initOAuthProviders();
    const oauthProviders = (await import('./lib/oauth.js')).getEnabledProviders();
    if (oauthProviders.length > 0) {
      fastify.log.info(`🔑 OAuth providers enabled: ${oauthProviders.join(', ')}`);
    }

    // Register plugins and routes
    await registerPlugins();
    setupHealthCheck();
    setupSystemStatus();
    setupCsrfEndpoint();
    
    // Register CSRF protection middleware globally
    fastify.addHook('preHandler', csrfProtection);
    
    await registerRoutes();

    // Start server
    const address = await fastify.listen({
      port: appConfig.PORT,
      host: '0.0.0.0',
    });

    fastify.log.info(`🌐 Server listening on ${address}`);
    
    // Start scheduler only if enabled
    if (appConfig.SCHEDULER_ENABLED) {
      scheduler.start();
      fastify.log.info('⏰ Scheduler auto-started');
    } else {
      fastify.log.info('⏰ Scheduler disabled (SCHEDULER_ENABLED=false)');
    }

    fastify.log.info('✅ SkinBaron Tracker API initialized successfully!');
    
  } catch (error) {
    fastify.log.fatal({ error }, 'Failed to initialize application');
    process.exit(1);
  }
}

// Start the application
initializeApp().catch(() => {
  process.exit(1);
});

export { fastify };
export default fastify;