import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
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

  // Authentication hook
  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    const { authMiddleware } = await import('./lib/middleware.js');
    await authMiddleware(request, reply);
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
    let schedulerHealth = 'unhealthy';
    try {
      const schedulerStats = getScheduler().getStats();
      schedulerHealth = schedulerStats.isRunning ? 'running' : 'stopped';
    } catch (error) {
      schedulerHealth = 'unhealthy';
    }

    // Check SkinBaron API health
    let skinbaronHealth = 'unhealthy';
    try {
      const skinbaronClient = getSkinBaronClient();
      const isConnected = await skinbaronClient.testConnection();
      skinbaronHealth = isConnected ? 'healthy' : 'unhealthy';
    } catch (error) {
      skinbaronHealth = 'unhealthy';
    }
    
    // Determine overall status
    const services = {
      database: dbHealth,
      skinbaron_api: skinbaronHealth,
      scheduler: schedulerHealth
    };
    
    // Consider 'running' as healthy for scheduler, 'healthy' for others
    const isHealthy = (service: string, status: string) => {
      if (service === 'scheduler') return status === 'running' || status === 'healthy';
      return status === 'healthy';
    };
    
    const allServicesHealthy = Object.entries(services).every(([service, status]) => 
      isHealthy(service, status)
    );
    
    const status = allServicesHealthy ? 'healthy' : 'degraded';

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

// System status endpoint - Simplified for users
async function setupSystemStatus() {
  fastify.get('/api/system/status', async (request, reply) => {
    try {
      const scheduler = getScheduler();

      // Get simplified scheduler status (read-only for users)
      const schedulerStats = scheduler.getStats();
      
      // Only return essential information for users
      const simplifiedStatus = {
        isRunning: schedulerStats.isRunning,
        lastRunTime: schedulerStats.lastRunTime,
        nextRunTime: schedulerStats.nextRunTime,
        totalRuns: schedulerStats.totalRuns,
        totalAlerts: schedulerStats.totalAlerts,
      };

      return reply.code(200).send({
        success: true,
        data: {
          scheduler: simplifiedStatus,
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





// Register API routes
async function registerRoutes() {
  // Import auth routes
  const { default: authRoutes } = await import('./routes/auth.js');
  const { default: webhooksRoutes } = await import('./routes/webhooks.js');
  
  // Authentication
  await fastify.register(authRoutes, { prefix: '/api/auth' });
  
  // User webhooks management
  await fastify.register(webhooksRoutes, { prefix: '/api/webhooks' });
  
  // Rules CRUD
  await fastify.register(rulesRoutes, { prefix: '/api/rules' });
  await fastify.register(alertsRoutes, { prefix: '/api/alerts' });
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