import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
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
  // Security middleware
  await fastify.register(helmet, {
    contentSecurityPolicy: false, // Disable for API
  });

  // CORS
  await fastify.register(cors, {
    origin: (origin, callback) => {
      // Allow requests from frontend or no origin (e.g., mobile apps)
      if (!origin || origin === appConfig.CORS_ORIGIN) {
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
    errorResponseBuilder: (request, context) => ({
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests, please try again in ${Math.ceil(context.ttl / 1000)} seconds`,
    }),
  });
}

// Health check endpoint
async function setupHealthCheck() {
  fastify.get('/health', {
    schema: {
      description: 'Health check endpoint',
      tags: ['System'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            status: { type: 'string' },
            timestamp: { type: 'string' },
            services: {
              type: 'object',
              properties: {
                database: { type: 'string' },
                skinbaron_api: { type: 'string' },
                scheduler: { type: 'string' },
              },
            },
            stats: {
              type: 'object',
              properties: {
                uptime: { type: 'number' },
                memory: { type: 'object' },
                version: { type: 'string' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const store = getStore();
      const skinBaronClient = getSkinBaronClient();
      const scheduler = getScheduler();

      // Check services
      const services = {
        database: 'unknown',
        skinbaron_api: 'unknown',
        scheduler: 'unknown',
      };

      // Test database
      try {
        store.getStats();
        services.database = 'healthy';
      } catch (error) {
        services.database = 'unhealthy';
      }

      // Test SkinBaron API (quick test)
      try {
        const apiHealthy = await skinBaronClient.testConnection();
        services.skinbaron_api = apiHealthy ? 'healthy' : 'unhealthy';
      } catch (error) {
        services.skinbaron_api = 'unhealthy';
      }

      // Check scheduler
      try {
        const schedulerStats = scheduler.getStats();
        services.scheduler = schedulerStats.isRunning ? 'running' : 'stopped';
      } catch (error) {
        services.scheduler = 'unhealthy';
      }

      const healthStatus = Object.values(services).every(status => 
        status === 'healthy' || status === 'running'
      ) ? 'healthy' : 'degraded';

      return reply.code(200).send({
        success: true,
        status: healthStatus,
        timestamp: new Date().toISOString(),
        services,
        stats: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          version: process.env.npm_package_version || '1.0.0',
        },
      });
    } catch (error) {
      return reply.code(503).send({
        success: false,
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}

// System status endpoint
async function setupSystemStatus() {
  fastify.get('/status', {
    schema: {
      description: 'System status and statistics',
      tags: ['System'],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                scheduler: { type: 'object' },
                database: { type: 'object' },
                config: { type: 'object' },
              },
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const store = getStore();
      const scheduler = getScheduler();

      const schedulerStats = scheduler.getStats();
      const databaseStats = store.getStats();

      return reply.code(200).send({
        success: true,
        data: {
          scheduler: schedulerStats,
          database: databaseStats,
          config: {
            nodeEnv: appConfig.NODE_ENV,
            pollCron: appConfig.POLL_CRON,
            enableBestDeals: appConfig.ENABLE_BEST_DEALS,
            enableNewestItems: appConfig.ENABLE_NEWEST_ITEMS,
            feedsMaxPrice: appConfig.FEEDS_MAX_PRICE,
            feedsMaxWear: appConfig.FEEDS_MAX_WEAR,
          },
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get system status');
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve system status',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}

// Scheduler control endpoints
async function setupSchedulerControls() {
  // Start scheduler
  fastify.post('/scheduler/start', {
    schema: {
      description: 'Start the alert scheduler',
      tags: ['Scheduler'],
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
      const scheduler = getScheduler();
      scheduler.start();
      
      return reply.code(200).send({
        success: true,
        message: 'Scheduler started successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to start scheduler');
      return reply.code(500).send({
        success: false,
        error: 'Failed to start scheduler',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Stop scheduler
  fastify.post('/scheduler/stop', {
    schema: {
      description: 'Stop the alert scheduler',
      tags: ['Scheduler'],
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
      const scheduler = getScheduler();
      scheduler.stop();
      
      return reply.code(200).send({
        success: true,
        message: 'Scheduler stopped successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to stop scheduler');
      return reply.code(500).send({
        success: false,
        error: 'Failed to stop scheduler',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });

  // Force run scheduler
  fastify.post('/scheduler/run', {
    schema: {
      description: 'Force run a scheduler cycle',
      tags: ['Scheduler'],
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
      const scheduler = getScheduler();
      await scheduler.forceRun();
      
      return reply.code(200).send({
        success: true,
        message: 'Scheduler cycle completed successfully',
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to run scheduler');
      return reply.code(500).send({
        success: false,
        error: 'Failed to run scheduler',
        message: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}

// Register API routes
async function setupRoutes() {
  // API routes
  await fastify.register(rulesRoutes, { prefix: '/rules' });
  await fastify.register(alertsRoutes, { prefix: '/alerts' });
  
  // System endpoints
  await setupHealthCheck();
  await setupSystemStatus();
  await setupSchedulerControls();
}

// Initialize application
async function initializeApp() {
  try {
    fastify.log.info('🚀 Initializing SkinBaron Alerts API...');

    // Initialize core services
    fastify.log.info('📊 Initializing database...');
    const store = getStore();
    
    fastify.log.info('🔍 Initializing SkinBaron client...');
    const skinBaronClient = getSkinBaronClient();
    
    fastify.log.info('🔔 Initializing notification service...');
    const notificationService = getNotificationService();
    
    fastify.log.info('⏰ Initializing scheduler...');
    const scheduler = getScheduler();

    // Register plugins and routes
    await registerPlugins();
    await setupRoutes();

    // Start server
    const address = await fastify.listen({
      port: appConfig.PORT,
      host: '0.0.0.0',
    });

    fastify.log.info(`🌐 Server listening on ${address}`);
    
    // Auto-start scheduler in production
    if (appConfig.NODE_ENV === 'production') {
      scheduler.start();
      fastify.log.info('⏰ Scheduler auto-started in production mode');
    }

    fastify.log.info('✅ SkinBaron Alerts API initialized successfully!');
    
  } catch (error) {
    fastify.log.fatal({ error }, 'Failed to initialize application');
    process.exit(1);
  }
}

// Start the application
initializeApp().catch((error) => {
  console.error('Fatal error during initialization:', error);
  process.exit(1);
});

export { fastify };
export default fastify;