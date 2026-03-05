import { CronJob } from 'cron';
import pino from 'pino';
import { appConfig } from './config.js';
import { store } from '../database/index.js';
import type { Rule } from '../database/validation-schemas.js';
import { getNotificationService } from './notifier.js';
import { runSchedulerMaintenance } from './scheduler/maintenance.js';
import { processRuleGroup } from './scheduler/rule-processing.js';
import type { SchedulerLogger, SchedulerStats } from './scheduler/types.js';

export class AlertScheduler {
  private logger: SchedulerLogger = pino({ level: appConfig.LOG_LEVEL });
  private cronJob: CronJob | null = null;
  private notificationService = getNotificationService();
  private lastCleanupTime = 0;
  private polling = false;

  private stats: SchedulerStats = {
    isRunning: false,
    lastRunTime: null,
    nextRunTime: null,
    totalRuns: 0,
    totalAlerts: 0,
    errorCount: 0,
    lastError: null,
  };

  setLogger(logger: SchedulerLogger) {
    this.logger = logger;
  }

  start(): void {
    if (this.cronJob) {
      return;
    }

    try {
      this.cronJob = new CronJob(
        appConfig.POLL_CRON,
        () => {
          void this.executePoll();
        },
        null,
        true,
        appConfig.SCHEDULER_TIMEZONE,
      );

      this.stats.isRunning = true;
      this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
    } catch (error) {
      this.recordError(error);
    }
  }

  stop(): void {
    if (this.cronJob) {
      void this.cronJob.stop();
      this.cronJob = null;
      this.stats.isRunning = false;
      this.stats.nextRunTime = null;
    }
  }

  async forceRun(): Promise<void> {
    await this.executePoll();
  }

  private async executePoll(): Promise<void> {
    if (this.polling) {
      this.logger.warn({}, '[Scheduler] Skipping poll — previous execution still running');
      return;
    }

    this.polling = true;
    try {
      await this.executePollInner();
    } finally {
      this.polling = false;
    }
  }

  private async executePollInner(): Promise<void> {
    this.stats.lastRunTime = new Date();
    this.stats.totalRuns++;

    try {
      this.lastCleanupTime = await runSchedulerMaintenance(this.logger, this.lastCleanupTime);

      const rules = await store.rules.findAllEnabled();
      if (rules.length === 0) {
        this.updateNextRunTime();
        return;
      }

      const groups = this.groupRulesBySearchTerm(rules);

      this.logger.info({
        totalRules: rules.length,
        uniqueSearchTerms: groups.length,
        apiCallsSaved: rules.length - groups.length,
      }, '[Scheduler] Grouped rules — deduplicating API calls');

      const API_CONCURRENCY = 3;
      const BATCH_DELAY = 500;
      let totalNewAlerts = 0;

      for (let i = 0; i < groups.length; i += API_CONCURRENCY) {
        const batch = groups.slice(i, i + API_CONCURRENCY);

        const results = await Promise.all(
          batch.map(group =>
            processRuleGroup(group, {
              logger: this.logger,
              notificationService: this.notificationService,
              onError: (error) => this.recordError(error),
            }).catch((error: unknown) => {
              this.recordError(error);
              this.logger.error({ error: String(error), searchItem: group[0]?.search_item }, '[Scheduler] Rule group failed');
              return 0;
            }),
          ),
        );

        totalNewAlerts += results.reduce((sum, count) => sum + count, 0);

        if (i + API_CONCURRENCY < groups.length) {
          await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
        }
      }

      this.stats.totalAlerts += totalNewAlerts;
      this.updateNextRunTime();
    } catch (error) {
      this.recordError(error);
    }
  }

  private groupRulesBySearchTerm(rules: Rule[]): Rule[][] {
    const ruleGroups = new Map<string, Rule[]>();

    for (const rule of rules) {
      const key = rule.search_item.trim().toLowerCase();
      const group = ruleGroups.get(key) ?? [];
      group.push(rule);
      ruleGroups.set(key, group);
    }

    return Array.from(ruleGroups.values());
  }

  private recordError(error: unknown): void {
    this.stats.errorCount++;
    this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
  }

  private updateNextRunTime(): void {
    if (this.cronJob) {
      this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
    }
  }

  getStats(): SchedulerStats {
    if (this.cronJob && this.stats.isRunning) {
      this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
    }
    return { ...this.stats };
  }

  resetStats(): void {
    this.stats = {
      isRunning: this.stats.isRunning,
      lastRunTime: null,
      nextRunTime: this.stats.nextRunTime,
      totalRuns: 0,
      totalAlerts: 0,
      errorCount: 0,
      lastError: null,
    };
  }
}

let schedulerInstance: AlertScheduler | null = null;

export const getScheduler = (): AlertScheduler => {
  if (!schedulerInstance) {
    schedulerInstance = new AlertScheduler();
  }
  return schedulerInstance;
};
