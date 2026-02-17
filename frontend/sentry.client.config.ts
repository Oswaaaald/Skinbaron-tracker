import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env['NEXT_PUBLIC_SENTRY_DSN'],
  environment: process.env['NODE_ENV'] ?? 'development',

  // Performance monitoring — sample 10% of transactions in prod
  tracesSampleRate: process.env['NODE_ENV'] === 'production' ? 0.1 : 1.0,

  // Session replay — capture 0% baseline, 100% on error
  replaysSessionSampleRate: 0,
  replaysOnErrorSampleRate: 1.0,

  // Don't send PII
  sendDefaultPii: false,

  integrations: [
    Sentry.replayIntegration(),
  ],
});
