import type { FastifyInstance } from 'fastify';
import rulesRoutes from '../routes/rules.js';
import alertsRoutes from '../routes/alerts.js';

export async function registerRoutes(fastify: FastifyInstance): Promise<void> {
  const { readAvatarFile } = await import('../lib/avatar.js');
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
      .header('Cache-Control', 'public, max-age=2592000, immutable')
      .header('X-Content-Type-Options', 'nosniff')
      .header('Cross-Origin-Resource-Policy', 'cross-origin')
      .header('Content-Security-Policy', "default-src 'none'; img-src 'self'")
      .send(data);
  });

  const { default: authRoutes } = await import('../routes/auth.js');
  const { default: webhooksRoutes } = await import('../routes/webhooks.js');
  const { default: itemsRoutes } = await import('../routes/items.js');
  const { default: userRoutes } = await import('../routes/user.js');
  const { default: adminRoutes } = await import('../routes/admin.js');

  await fastify.register(authRoutes, { prefix: '/api/auth' });
  await fastify.register(userRoutes, { prefix: '/api/user' });
  await fastify.register(webhooksRoutes, { prefix: '/api/webhooks' });
  await fastify.register(rulesRoutes, { prefix: '/api/rules' });
  await fastify.register(alertsRoutes, { prefix: '/api/alerts' });
  await fastify.register(itemsRoutes, { prefix: '/api/items' });
  await fastify.register(adminRoutes, { prefix: '/api/admin' });
}
