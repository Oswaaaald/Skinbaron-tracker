import { appConfig } from '../config.js';
import { store } from '../../database/index.js';
import type { SchedulerLogger } from './types.js';
import { runSecurityCleanup } from '../security-cleanup.js';

const ONE_DAY_MS = 86_400_000;

export async function runSchedulerMaintenance(logger: SchedulerLogger, lastCleanupTime: number): Promise<number> {
  const now = Date.now();
  let nextCleanupTime = lastCleanupTime;

  if (now - lastCleanupTime >= ONE_DAY_MS) {
    nextCleanupTime = now;

    try {
      const result = await store.audit.cleanupOldLogs(appConfig.AUDIT_LOG_RETENTION_DAYS);
      if (result > 0) {
        logger.info({ deleted: result, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old audit logs');
      }
    } catch (error) {
      logger.error({ error }, '[Scheduler] Failed to clean old audit logs');
    }

    try {
      const result = await store.audit.cleanupOldAdminActions(appConfig.AUDIT_LOG_RETENTION_DAYS);
      if (result > 0) {
        logger.info({ deleted: result, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old admin actions');
      }
    } catch (error) {
      logger.error({ error }, '[Scheduler] Failed to clean old admin actions');
    }

    try {
      const result = await store.alerts.cleanupOldAlerts(appConfig.ALERT_RETENTION_DAYS);
      if (result > 0) {
        logger.info({ deleted: result, retentionDays: appConfig.ALERT_RETENTION_DAYS }, '[Scheduler] Cleaned old alerts');
      }
    } catch (error) {
      logger.error({ error }, '[Scheduler] Failed to clean old alerts');
    }
  }

  await runSecurityCleanup(logger, '[Scheduler]');

  return nextCleanupTime;
}
