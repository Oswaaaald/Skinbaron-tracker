import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cookie from '@fastify/cookie';
import { appConfig } from './lib/config.js';
import { store } from './database/index.js';
import { closeDatabase } from './database/connection.js';
import { getSkinBaronClient } from './lib/sbclient.js';
import { getNotificationService } from './lib/notifier.js';
import { getScheduler } from './lib/scheduler.js';
import { handleRouteError } from './lib/validation-handler.js';
import rulesRoutes from './routes/rules.js';
import alertsRoutes from './routes/alerts.js';

// Create Fastify instance
const fastify = Fastify({
  logger: {
    level: appConfig.LOG_LEVEL,
  },
  // Respect X-Forwarded-* headers from the reverse proxy for accurate client IPs
  trustProxy: true,
  // Custom error formatter for validation errors (makes them user-friendly)
  schemaErrorFormatter: (errors, _dataVar) => {
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
        ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at least ${error.params['limit']} characters`
        : `Must be at least ${error.params['limit']} characters`;
    } else if (error.keyword === 'maxLength') {
      message = field
        ? `${field.charAt(0).toUpperCase() + field.slice(1)} must be at most ${error.params['limit']} characters`
        : `Must be at most ${error.params['limit']} characters`;
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
      message = `${field || 'Field'} must be at least ${error.params['limit']}`;
    } else if (error.keyword === 'maximum') {
      message = `${field || 'Field'} must be at most ${error.params['limit']}`;
    } else if (error.keyword === 'enum') {
      const allowedValues = error.params['allowedValues'] as string[] | undefined;
      message = `${field || 'Field'} must be one of: ${allowedValues?.join(', ') || 'allowed values'}`;
    } else if (error.keyword === 'type') {
      message = `${field || 'Field'} must be a ${error.params['type']}`;
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
    
    // Close database with optimization
    closeDatabase();
    
    // Close Fastify
    await fastify.close();
    
    fastify.log.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    fastify.log.error({ error }, 'Error during shutdown');
    process.exit(1);
  }
};

// Setup graceful shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Error handlers
process.on('uncaughtException', (error) => {
  fastify.log.fatal({ error }, 'Uncaught Exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  fastify.log.fatal({ promise, reason }, 'Unhandled Rejection');
  process.exit(1);
});

// Register plugins
async function registerPlugins() {
  await fastify.register(cookie, {
    hook: 'onRequest',
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
      const configuredOrigins = appConfig.CORS_ORIGINS
        ? appConfig.CORS_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
        : [];
      const allowedOrigins = Array.from(new Set([
        appConfig.CORS_ORIGIN,
        ...configuredOrigins,
      ])).filter(Boolean);
      
      // Allow requests with no origin (e.g., mobile apps, Postman)
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
    allowedHeaders: ['Content-Type', 'Authorization'],
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
      const cfConnectingIp = request.headers['cf-connecting-ip'];
      if (typeof cfConnectingIp === 'string' && cfConnectingIp.trim()) {
        return cfConnectingIp.trim();
      }

      const realIp = request.headers['x-real-ip'];
      if (typeof realIp === 'string' && realIp.trim()) {
        return realIp.trim();
      }

      const forwardedFor = request.headers['x-forwarded-for'];
      if (typeof forwardedFor === 'string' && forwardedFor.trim().length > 0) {
        const clientIp = forwardedFor.split(',')[0];
        if (clientIp) {
          return clientIp.trim();
        }
      }

      const cookies = request.cookies as Record<string, string | undefined> | undefined;
      const accessToken = cookies?.['access_token'];
      const refreshToken = cookies?.['refresh_token'];
      return accessToken ?? refreshToken ?? request.ip ?? 'unknown';
    },
    errorResponseBuilder: (_request, context) => ({
      statusCode: 429,
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests, please try again in ${Math.ceil(context.ttl / 1000)} seconds`,
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
    
    if (error instanceof AppError) {
      return handleRouteError(error, request, reply, 'Global handler');
    }
    
    // Let other errors fall through to default handler
    throw error;
  });
}

async function buildSystemSnapshot() {
  const scheduler = getScheduler();

  // Check database health
  let dbHealth = 'healthy';
  try {
    await store.getStats();
  } catch (_error) {
    dbHealth = 'unhealthy';
  }

  // Scheduler health and stats
  let schedulerHealth = 'unhealthy';
  let simplifiedScheduler: Record<string, string | number | boolean | null | Date> = {};
  try {
    const schedulerStats = scheduler.getStats();
    schedulerHealth = schedulerStats.isRunning ? 'running' : 'stopped';
    simplifiedScheduler = {
      isRunning: schedulerStats.isRunning,
      lastRunTime: schedulerStats.lastRunTime,
      nextRunTime: schedulerStats.nextRunTime,
      totalRuns: schedulerStats.totalRuns,
      totalAlerts: schedulerStats.totalAlerts,
    };
  } catch (_error) {
    schedulerHealth = 'unhealthy';
  }

  // SkinBaron API health (lightweight check)
  let skinbaronHealth = 'unhealthy';
  try {
    const skinbaronClient = getSkinBaronClient();
    const healthStatus = skinbaronClient.getHealthStatus();
    if (healthStatus === 'unknown') {
      const isConnected = await skinbaronClient.testConnection();
      skinbaronHealth = isConnected ? 'healthy' : 'unhealthy';
    } else {
      skinbaronHealth = healthStatus;
    }
  } catch (_error) {
    skinbaronHealth = 'unhealthy';
  }

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

// Health check endpoint
async function setupHealthCheck() {
  fastify.get('/api/health', {
    logLevel: 'warn'
  }, async (_request, reply) => {
    const snapshot = await buildSystemSnapshot();
    const { health } = snapshot;
    return reply.status(200).send({ success: true, ...health });
  });
}

// System status endpoint - now includes health snapshot
async function setupSystemStatus() {
  fastify.get('/api/system/status', async (request, reply) => {
    try {
      const snapshot = await buildSystemSnapshot();
      return reply.status(200).send({
        success: true,
        data: {
          scheduler: snapshot.scheduler,
          health: snapshot.health,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get system status');
    }
  });
}





// Register API routes
async function registerRoutes() {
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
    // Database auto-initialized via singleton
    
    fastify.log.info('🔍 Initializing SkinBaron client...');
    getSkinBaronClient();
    
    fastify.log.info('🔔 Initializing notification service...');
    getNotificationService();
    
    fastify.log.info('⏰ Initializing scheduler...');
    const scheduler = getScheduler();

    // Register plugins and routes
    await registerPlugins();
    await setupHealthCheck();
    await setupSystemStatus();
    await registerRoutes();

    // Start server
    const address = await fastify.listen({
      port: appConfig.PORT,
      host: '0.0.0.0',
    });

    fastify.log.info(`🌐 Server listening on ${address}`);
    
    // Auto-start scheduler in all environments
    scheduler.start();
    fastify.log.info('⏰ Scheduler auto-started');

    fastify.log.info('✅ SkinBaron Tracker API initialized successfully!');
    
  } catch (error) {
    fastify.log.fatal({ error }, 'Failed to initialize application');
    process.exit(1);
  }
}

// Start the application
initializeApp().catch((_error) => {
  process.exit(1);
});

export { fastify };
export default fastify;