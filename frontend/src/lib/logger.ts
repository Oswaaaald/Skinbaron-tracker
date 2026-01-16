/**
 * Client-side Logger
 * 
 * Development-only logging utility.
 * In production, logs are silent (can be extended to send to monitoring service).
 */

const isDevelopment = process.env['NODE_ENV'] === 'development';

export const logger = {
  info: (message: string, ...args: unknown[]) => {
    if (isDevelopment) {
      console.log(`[INFO] ${message}`, ...args);
    }
  },

  warn: (message: string, ...args: unknown[]) => {
    if (isDevelopment) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  },

  error: (message: string, error?: unknown) => {
    if (isDevelopment) {
      console.error(`❌ ${message}`, error);
    }
    // In production, could send to Sentry/monitoring service
  },
};
