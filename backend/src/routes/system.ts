import type { FastifyInstance } from 'fastify';
import { appConfig } from '../lib/config.js';
import { store } from '../database/index.js';
import { checkDatabaseHealth } from '../database/connection.js';
import { getSkinBaronClient } from '../lib/sbclient.js';
import { getScheduler } from '../lib/scheduler.js';
import { handleRouteError } from '../lib/validation-handler.js';
import { generateCsrfToken, setCsrfCookie } from '../lib/csrf.js';

type SimplifiedScheduler = Record<string, string | number | boolean | null>;

async function buildSystemSnapshot(fastify: FastifyInstance): Promise<{
  health: {
    status: 'healthy' | 'degraded';
    timestamp: string;
    services: {
      database: string;
      skinbaron_api: string;
      scheduler: string;
    };
    stats: {
      uptime: number;
      memory: NodeJS.MemoryUsage;
      version: string;
    };
  };
  scheduler: SimplifiedScheduler;
}> {
  const scheduler = getScheduler();

  // Scheduler health and stats (synchronous / in-memory — always fast)
  let schedulerHealth = 'unhealthy';
  let simplifiedScheduler: SimplifiedScheduler = {};
  try {
    const schedulerStats = scheduler.getStats();
    // Scheduler is healthy if running, or if stopped but has no errors
    schedulerHealth = schedulerStats.isRunning
      ? 'running'
      : (schedulerStats.errorCount === 0 ? 'stopped' : 'unhealthy');
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
      .then((ok) => (ok ? 'healthy' : 'unhealthy'))
      .catch((error) => {
        fastify.log.error({ error }, 'Database health check failed');
        return 'unhealthy';
      }),
    getSkinBaronClient().testConnection()
      .then((ok) => (ok ? 'healthy' : 'unhealthy'))
      .catch((error) => {
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
    isHealthy(service, status),
  );

  return {
    health: {
      status: allServicesHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      services,
      stats: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: appConfig.APP_VERSION,
      },
    },
    scheduler: simplifiedScheduler,
  };
}

// robots.txt - allow frontend page indexing, block API and admin routes
function setupRobotsTxt(fastify: FastifyInstance): void {
  fastify.get('/robots.txt', {
    logLevel: 'warn',
    schema: { hide: true },
  }, async (_request, reply) => {
    return reply
      .type('text/plain')
      .send(
        'User-agent: *\n'
        + 'Allow: /\n'
        + 'Disallow: /api/\n'
        + 'Disallow: /admin\n',
      );
  });
}

// Health check endpoint - lightweight, no external dependencies
function setupHealthCheck(fastify: FastifyInstance): void {
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
function setupSystemStatus(fastify: FastifyInstance): void {
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
      const snapshot = await buildSystemSnapshot(fastify);
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
function setupCsrfEndpoint(fastify: FastifyInstance): void {
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

export function registerSystemRoutes(fastify: FastifyInstance): void {
  setupRobotsTxt(fastify);
  setupHealthCheck(fastify);
  setupSystemStatus(fastify);
  setupCsrfEndpoint(fastify);
}
