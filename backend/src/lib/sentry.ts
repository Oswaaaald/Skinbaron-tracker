import * as Sentry from '@sentry/node';
import { appConfig } from './config.js';

/**
 * Initialize Sentry error tracking.
 * Call this as early as possible in the application lifecycle.
 */
export function initSentry(): void {
  if (!appConfig.SENTRY_DSN) return;

  Sentry.init({
    dsn: appConfig.SENTRY_DSN,
    environment: appConfig.NODE_ENV,
    release: appConfig.APP_VERSION,
    tracesSampleRate: appConfig.NODE_ENV === 'production' ? 0.1 : 1.0,

    // Don't send PII by default
    sendDefaultPii: false,

    // Filter out noisy/expected errors
    beforeSend(event, hint) {
      const error = hint.originalException;

      // Skip expected operational errors (4xx)
      if (
        error &&
        typeof error === 'object' &&
        'statusCode' in error &&
        typeof (error as { statusCode: unknown }).statusCode === 'number' &&
        (error as { statusCode: number }).statusCode < 500
      ) {
        return null;
      }

      return event;
    },

    integrations: [
      // Capture unhandled promise rejections and uncaught exceptions
      Sentry.onUnhandledRejectionIntegration(),
      Sentry.onUncaughtExceptionIntegration({ exitEvenIfOtherHandlersAreRegistered: false }),
    ],
  });
}

/**
 * Capture an exception in Sentry (no-op if Sentry is not configured).
 */
export function captureException(error: unknown, context?: Record<string, unknown>): void {
  if (!appConfig.SENTRY_DSN) return;
  Sentry.captureException(error, context ? { extra: context } : undefined);
}

/**
 * Flush pending events before shutdown.
 */
export async function flushSentry(timeout = 2000): Promise<void> {
  if (!appConfig.SENTRY_DSN) return;
  await Sentry.flush(timeout);
}
