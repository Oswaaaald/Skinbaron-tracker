import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cookie from '@fastify/cookie';
import { appConfig } from './lib/config.js';
import { getStore } from './lib/store.js';
import { getSkinBaronClient } from './lib/sbclient.js';
import { getNotificationService } from './lib/notifier.js';
import { getScheduler } from './lib/scheduler.js';
import rulesRoutes from './routes/rules.js';
import alertsRoutes from './routes/alerts.js';

// Create Fastify instance
const fastify = Fastify({
  logger: {
    level: appConfig.LOG_LEVEL,
  },
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
    
    // Close database
    const store = getStore();
    store.close();
    
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
    contentSecurityPolicy: false, // Disable for API
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
        'https://skinbaron-tracker.oswaaaald.be',
        'http://localhost:3000',
      ]));
      
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
  });

  // Rate limiting
  await fastify.register(rateLimit, {
    max: appConfig.RATE_LIMIT_MAX,
    timeWindow: appConfig.RATE_LIMIT_WINDOW,
    errorResponseBuilder: (_request, context) => ({
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests, please try again in ${Math.ceil(context.ttl / 1000)} seconds`,
    }),
  });

  // Authentication hook
  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    const { authMiddleware } = await import('./lib/middleware.js');
    await authMiddleware(request, reply);
  });

  // Admin authentication hook
  fastify.decorate('requireAdmin', async (request: FastifyRequest, reply: FastifyReply) => {
    const { requireAdminMiddleware } = await import('./lib/middleware.js');
    await requireAdminMiddleware(request, reply);
  });

  // Super Admin authentication hook
  fastify.decorate('requireSuperAdmin', async (request: FastifyRequest, reply: FastifyReply) => {
    const { requireSuperAdminMiddleware } = await import('./lib/middleware.js');
    await requireSuperAdminMiddleware(request, reply);
  });
}

async function buildSystemSnapshot() {
  const store = getStore();
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
  let simplifiedScheduler: Record<string, any> = {};
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
      request.log.error({ error }, 'Failed to get system status');
      return reply.status(500).send({
        success: false,
        error: 'Failed to retrieve system status',
      });
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
    getStore();
    
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