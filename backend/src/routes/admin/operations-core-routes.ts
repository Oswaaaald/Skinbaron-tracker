import type { FastifyInstance } from 'fastify';
import { store } from '../../database/index.js';
import { getScheduler } from '../../lib/scheduler.js';
import { getAuthUser } from '../../lib/middleware.js';
import { handleRouteError } from '../../lib/validation-handler.js';
import { Errors } from '../../lib/errors.js';
import { appConfig } from '../../lib/config.js';
import { captureException, verifySentryConnection } from '../../lib/sentry.js';
import type { RegisterAdminRouteOptions } from './types.js';

export function registerAdminOperationalCoreRoutes(
  fastify: FastifyInstance,
  { adminWriteRateLimit }: RegisterAdminRouteOptions,
): void {
  const scheduler = getScheduler();

  fastify.get('/stats', {
    schema: {
      description: 'Get global statistics (admin only)',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            data: {
              type: 'object',
              properties: {
                users: { type: 'number' },
                admins: { type: 'number' },
                rules: { type: 'number' },
                enabled_rules: { type: 'number' },
                alerts: { type: 'number' },
                webhooks: { type: 'number' },
              },
              additionalProperties: true,
            },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      const stats = await store.audit.getGlobalStats();
      return reply.status(200).send({
        success: true,
        data: {
          ...stats,
          sentryEnabled: !!appConfig.SENTRY_DSN,
        },
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Get global stats');
    }
  });

  fastify.post('/scheduler/force-run', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    schema: {
      description: 'Force the scheduler to run immediately (bypasses cron schedule) - Admin only',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
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
      await scheduler.forceRun();

      await store.audit.logAdminAction(getAuthUser(request).id, 'force_scheduler', null, 'Manually triggered scheduler run');

      return reply.status(200).send({
        success: true,
        message: 'Scheduler executed successfully',
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Force scheduler run');
    }
  });

  fastify.post('/test-sentry', {
    config: {
      rateLimit: adminWriteRateLimit,
    },
    preHandler: [fastify.requireSuperAdmin],
    schema: {
      description: 'Trigger a test error that is captured by Sentry - Super Admin only',
      tags: ['Admin'],
      security: [{ bearerAuth: [] }, { cookieAuth: [] }],
      response: {
        200: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            message: { type: 'string' },
            verified: { type: 'boolean' },
          },
        },
      },
    },
  }, async (request, reply) => {
    try {
      if (!appConfig.SENTRY_DSN) {
        throw Errors.badRequest('Sentry is not configured — set SENTRY_DSN to enable');
      }

      const verification = await verifySentryConnection();
      if (!verification.ok) {
        throw Errors.badRequest(verification.reason ?? 'Sentry DSN verification failed');
      }

      const testError = new Error('Sentry test error — triggered by admin');
      captureException(testError, { triggeredBy: getAuthUser(request).id });

      await store.audit.logAdminAction(
        getAuthUser(request).id,
        'test_sentry',
        null,
        'Triggered a Sentry test error',
      );

      return reply.status(200).send({
        success: true,
        message: 'Test error sent to Sentry',
        verified: true,
      });
    } catch (error) {
      return handleRouteError(error, request, reply, 'Test Sentry');
    }
  });
}
