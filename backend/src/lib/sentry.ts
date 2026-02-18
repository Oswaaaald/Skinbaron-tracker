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

/**
 * Verify Sentry connectivity by probing the envelope ingest endpoint.
 * Returns `{ ok: true }` if the DSN is valid and the server is reachable,
 * or `{ ok: false, reason }` with a human-readable explanation.
 */
export async function verifySentryConnection(): Promise<{ ok: boolean; reason?: string }> {
  const dsn = appConfig.SENTRY_DSN;
  if (!dsn) {
    return { ok: false, reason: 'SENTRY_DSN is not configured' };
  }

  // DSN format: https://<public_key>@<host>/<project_id>
  const match = dsn.match(/^(https?):\/\/([^@]+)@([^/]+)\/(.+)$/);
  if (!match) {
    return { ok: false, reason: 'Invalid DSN format — expected https://<key>@<host>/<project_id>' };
  }

  const [, protocol, publicKey, host, projectId] = match;
  const envelopeUrl = `${protocol}://${host}/api/${projectId}/envelope/?sentry_key=${publicKey}&sentry_version=7`;

  try {
    const response = await fetch(envelopeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-sentry-envelope' },
      // Minimal envelope header — enough to probe connectivity
      body: `{"dsn":"${dsn}","sent_at":"${new Date().toISOString()}"}\n`,
      signal: AbortSignal.timeout(5000),
    });

    // 200 = valid, 400 = malformed but server is Sentry → connectivity OK
    if (response.ok || response.status === 400) {
      return { ok: true };
    }

    // 401/403 = wrong key, 404 = project doesn't exist
    return {
      ok: false,
      reason: `Sentry responded with HTTP ${response.status} — the DSN key or project may be invalid`,
    };
  } catch {
    return {
      ok: false,
      reason: `Cannot reach Sentry at ${host} — verify the DSN URL is correct`,
    };
  }
}
