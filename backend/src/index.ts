import { initSentry } from './lib/sentry.js';

initSentry();

import Fastify from 'fastify';
import { appConfig } from './lib/config.js';
import { initializeDatabase } from './database/connection.js';
import { getSkinBaronClient } from './lib/sbclient.js';
import { getNotificationService } from './lib/notifier.js';
import { getScheduler } from './lib/scheduler.js';
import { csrfProtection } from './lib/csrf.js';
import { initOAuthProviders, getEnabledProviders } from './lib/oauth.js';
import { registerSystemRoutes } from './routes/system.js';
import { registerPlugins } from './app/plugins.js';
import { registerRoutes } from './app/routes.js';
import { registerProcessHandlers } from './app/lifecycle.js';
import { schemaErrorFormatter } from './app/schema-error-formatter.js';

const trustProxyConfig = appConfig.TRUST_PROXY_HOPS > 0 ? appConfig.TRUST_PROXY_HOPS : false;

const fastify = Fastify({
  logger: {
    level: appConfig.LOG_LEVEL,
  },
  trustProxy: trustProxyConfig,
  schemaErrorFormatter,
});

getScheduler().setLogger(fastify.log);
registerProcessHandlers(fastify);

async function initializeApp() {
  try {
    fastify.log.info('🚀 Initializing SkinBaron Tracker API...');
    fastify.log.info({ trustProxyHops: appConfig.TRUST_PROXY_HOPS }, 'Proxy trust configuration');

    fastify.log.info('📊 Initializing database...');
    await initializeDatabase();
    fastify.log.info('✅ Database migrations applied');

    const { ensureUploadDir } = await import('./lib/avatar.js');
    await ensureUploadDir();
    fastify.log.info('✅ Avatar upload directory ready');

    fastify.log.info('🔍 Initializing SkinBaron client...');
    getSkinBaronClient();

    fastify.log.info('🔔 Initializing notification service...');
    getNotificationService();

    fastify.log.info('⏰ Initializing scheduler...');
    const scheduler = getScheduler();

    initOAuthProviders();
    const oauthProviders = getEnabledProviders();
    if (oauthProviders.length > 0) {
      fastify.log.info(`🔑 OAuth providers enabled: ${oauthProviders.join(', ')}`);
    }

    await registerPlugins(fastify);
    registerSystemRoutes(fastify);

    fastify.addHook('preHandler', csrfProtection);

    await registerRoutes(fastify);

    const address = await fastify.listen({
      port: appConfig.PORT,
      host: '0.0.0.0',
    });

    fastify.log.info(`🌐 Server listening on ${address}`);

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

initializeApp().catch(() => {
  process.exit(1);
});

export { fastify };
export default fastify;
