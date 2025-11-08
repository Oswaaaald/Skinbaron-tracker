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
import testRoutes from './routes/test.js';

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
  fastify.get('/api/health', async (request, reply) => {
    const store = getStore();
    const scheduler = getScheduler();
    
    // Check database health
    let dbHealth = 'healthy';
    try {
      await store.getStats(); // Simple check to see if DB is accessible
    } catch (error) {
      dbHealth = 'unhealthy';
    }
    
    // Check scheduler health
    let schedulerHealth = 'stopped';
    try {
      const schedulerStats = scheduler.getStats();
      schedulerHealth = schedulerStats.isRunning ? 'running' : 'stopped';
    } catch (error) {
      schedulerHealth = 'unhealthy';
    }
    
    // Determine overall status
    const services = {
      database: dbHealth,
      skinbaron_api: 'unhealthy', // Always unhealthy without API key
      scheduler: schedulerHealth
    };
    
    const status = Object.values(services).every(s => s === 'healthy') ? 'healthy' : 'degraded';

    return reply.code(200).send({
      success: true,
      status,
      timestamp: new Date().toISOString(),
      services,
      stats: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: '2.0.0',
      },
    });
  });
}

// System status endpoint - REAL DATA VERSION
async function setupSystemStatus() {
  fastify.get('/api/system/status', async (request, reply) => {
    try {
      const store = getStore();
      const scheduler = getScheduler();

      // Get real scheduler stats
      const schedulerStats = scheduler.getStats();
      
      // Get real database stats  
      const databaseStats = store.getStats();
      
      // Get real config data (only relevant system settings)
      const configData = {
        nodeEnv: appConfig.NODE_ENV,
        pollCron: appConfig.POLL_CRON,
      };

      return reply.code(200).send({
        success: true,
        data: {
          scheduler: schedulerStats,
          database: databaseStats,
          config: configData,
        },
      });
    } catch (error) {
      request.log.error({ error }, 'Failed to get system status');
      return reply.code(500).send({
        success: false,
        error: 'Failed to retrieve system status',
      });
    }
  });
}

// Scheduler control endpoints
async function setupSchedulerControls() {
  // Start scheduler
  fastify.post('/api/system/scheduler/start', async (request, reply) => {
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
  fastify.post('/api/system/scheduler/stop', async (request, reply) => {
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
  fastify.post('/api/system/scheduler/run', async (request, reply) => {
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
async function registerRoutes() {
  // Rules CRUD
  await fastify.register(rulesRoutes, { prefix: '/api/rules' });
  await fastify.register(alertsRoutes, { prefix: '/api/alerts' });
  await fastify.register(testRoutes);
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
    await setupHealthCheck();
    await setupSystemStatus();
    await setupSchedulerControls();
    await registerRoutes();

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