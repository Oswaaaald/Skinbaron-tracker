/**
 * Migration Logger
 * 
 * Utility for logging database migrations with structured output.
 * Falls back to console in development when Fastify logger is not available.
 */

export class MigrationLogger {
  private static instance: MigrationLogger;
  private logs: Array<{ level: string; message: string; timestamp: Date }> = [];

  private constructor() {}

  static getInstance(): MigrationLogger {
    if (!MigrationLogger.instance) {
      MigrationLogger.instance = new MigrationLogger();
    }
    return MigrationLogger.instance;
  }

  info(message: string, meta?: any) {
    const logEntry = {
      level: 'info',
      message,
      timestamp: new Date(),
      ...meta,
    };
    
    this.logs.push(logEntry);
    
    // In production, these will be picked up by the main logger
    if (process.env.NODE_ENV === 'development') {
      console.log(`ℹ️  ${message}`, meta || '');
    }
  }

  warn(message: string, meta?: any) {
    const logEntry = {
      level: 'warn',
      message,
      timestamp: new Date(),
      ...meta,
    };
    
    this.logs.push(logEntry);
    
    if (process.env.NODE_ENV === 'development') {
      console.warn(`⚠️  ${message}`, meta || '');
    }
  }

  error(message: string, error?: any) {
    const logEntry = {
      level: 'error',
      message,
      timestamp: new Date(),
      error: error?.message || error,
    };
    
    this.logs.push(logEntry);
    
    console.error(`❌ ${message}`, error || '');
  }

  getLogs() {
    return this.logs;
  }

  clearLogs() {
    this.logs = [];
  }
}

export const migrationLogger = MigrationLogger.getInstance();
