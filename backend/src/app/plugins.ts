import type { FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { appConfig, MAX_UPLOAD_SIZE } from '../lib/config.js';
import { ACCESS_COOKIE, baseCookieOptions, getClientIp } from '../lib/middleware.js';
import { OAUTH_STATE_COOKIE } from '../lib/oauth.js';
import { captureException } from '../lib/sentry.js';

export async function registerPlugins(fastify: FastifyInstance): Promise<void> {
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
      filter: true,
    },
    staticCSP: true,
    transformStaticCSP: (header) => header,
    transformSpecification: (swaggerObject, request) => {
      type OpenAPIOperation = {
        tags?: string[];
        [key: string]: unknown;
      };
      type OpenAPIPathMethods = Record<string, OpenAPIOperation>;
      type OpenAPITag = {
        name: string;
        description?: string;
      };

      const isAdmin = request.user?.is_admin || request.user?.is_super_admin;
      if (isAdmin) {
        return swaggerObject;
      }

      const hiddenTags = new Set(['Admin', 'System']);
      const filteredPaths: Record<string, OpenAPIPathMethods> = {};
      const usedTags = new Set<string>();
      const paths = (swaggerObject['paths'] || {}) as Record<string, OpenAPIPathMethods>;

      for (const [path, methods] of Object.entries(paths)) {
        const filteredMethods: OpenAPIPathMethods = {};

        for (const [verb, op] of Object.entries(methods)) {
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

      const filteredTags = ((swaggerObject['tags'] || []) as OpenAPITag[]).filter((tag: OpenAPITag) =>
        usedTags.has(tag.name),
      );

      return {
        ...swaggerObject,
        paths: filteredPaths,
        tags: filteredTags,
      } as typeof swaggerObject;
    },
    uiHooks: {
      onRequest: (request, reply, done) => {
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

  await fastify.register(multipart, {
    limits: {
      fileSize: MAX_UPLOAD_SIZE,
      files: 1,
      fields: 0,
    },
  });

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

  await fastify.register(cors, {
    origin: (origin, callback) => {
      const allowedOrigins = [
        appConfig.NEXT_PUBLIC_API_URL,
        appConfig.CORS_ORIGIN,
      ];

      if (!origin) {
        callback(null, true);
        return;
      }

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

  await fastify.register(rateLimit, {
    max: appConfig.RATE_LIMIT_MAX,
    timeWindow: appConfig.RATE_LIMIT_WINDOW,
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true,
    },
    keyGenerator: (request) => getClientIp(request),
    errorResponseBuilder: (request, context) => ({
      statusCode: 429,
      success: false,
      error: 'Rate limit exceeded',
      message: `Too many requests on ${request.method} ${request.url}, please try again in ${Math.ceil(context.ttl / 1000)} seconds`,
    }),
  });

  const { authMiddleware, requireAdmin, requireSuperAdmin } = await import('../lib/middleware.js');
  fastify.decorate('authenticate', authMiddleware);
  fastify.decorate('requireAdmin', requireAdmin);
  fastify.decorate('requireSuperAdmin', requireSuperAdmin);

  fastify.setErrorHandler(async (error, request, reply) => {
    const { AppError } = await import('../lib/errors.js');
    const { handleRouteError } = await import('../lib/validation-handler.js');

    if (
      request.method === 'GET' &&
      request.url.startsWith('/api/auth/oauth/') &&
      !request.url.endsWith('/providers')
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

    captureException(error, { url: request.url, method: request.method });
    throw error;
  });

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
