/**
 * Client-side Logger
 * 
 * Development-only logging utility.
 * In production, logs are silent (can be extended to send to monitoring service).
 */

const isDevelopment = process.env.NODE_ENV === 'development';

export const logger = {
  info: (message: string, ...args: any[]) => {
    if (isDevelopment) {
      console.log(`ℹ️ ${message}`, ...args);
    }
  },

  warn: (message: string, ...args: any[]) => {
    if (isDevelopment) {
      console.warn(`⚠️ ${message}`, ...args);
    }
  },

  error: (message: string, error?: any) => {
    if (isDevelopment) {
      console.error(`❌ ${message}`, error);
    }
    // In production, could send to Sentry/monitoring service
  },
};
