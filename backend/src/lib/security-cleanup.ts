import pino from 'pino';
import { appConfig } from './config.js';
import { store } from '../database/index.js';
import type { SchedulerLogger } from './scheduler/types.js';

export async function runSecurityCleanup(logger: SchedulerLogger, source: string): Promise<void> {
  try {
    await store.auth.cleanupExpiredBlacklistTokens();
  } catch (error) {
    logger.error({ error }, `${source} Failed to cleanup expired blacklist tokens`);
  }

  try {
    await store.auth.cleanupRefreshTokens();
  } catch (error) {
    logger.error({ error }, `${source} Failed to cleanup expired refresh tokens`);
  }

  try {
    await store.challenges.cleanup();
  } catch (error) {
    logger.error({ error }, `${source} Failed to cleanup expired pending challenges`);
  }
}

class SecurityCleanupService {
  private logger: SchedulerLogger = pino({ level: appConfig.LOG_LEVEL });
  private intervalRef: NodeJS.Timeout | null = null;

  setLogger(logger: SchedulerLogger) {
    this.logger = logger;
  }

  start(): void {
    if (this.intervalRef || appConfig.SECURITY_CLEANUP_INTERVAL_MS <= 0) {
      return;
    }

    void runSecurityCleanup(this.logger, '[SecurityCleanup]');
    this.intervalRef = setInterval(() => {
      void runSecurityCleanup(this.logger, '[SecurityCleanup]');
    }, appConfig.SECURITY_CLEANUP_INTERVAL_MS);
    this.intervalRef.unref();
  }

  stop(): void {
    if (!this.intervalRef) {
      return;
    }
    clearInterval(this.intervalRef);
    this.intervalRef = null;
  }
}

let cleanupService: SecurityCleanupService | null = null;

export function getSecurityCleanupService(): SecurityCleanupService {
  if (!cleanupService) {
    cleanupService = new SecurityCleanupService();
  }
  return cleanupService;
}
