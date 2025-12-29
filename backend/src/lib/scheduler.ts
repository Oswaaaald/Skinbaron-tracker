import { CronJob } from 'cron';
import { appConfig } from './config.js';
import { getStore, type Rule, type CreateAlert } from './store.js';
import { getSkinBaronClient, type SkinBaronItem } from './sbclient.js';
import { getNotificationService } from './notifier.js';

export interface SchedulerStats {
  isRunning: boolean;
  lastRunTime: Date | null;
  nextRunTime: Date | null;
  totalRuns: number;
  totalAlerts: number;
  errorCount: number;
  lastError: string | null;
}

export class AlertScheduler {
  private cronJob: CronJob | null = null;
  private store = getStore();
  private skinBaronClient = getSkinBaronClient();
  private notificationService = getNotificationService();

  // Statistics
  private stats: SchedulerStats = {
    isRunning: false,
    lastRunTime: null,
    nextRunTime: null,
    totalRuns: 0,
    totalAlerts: 0,
    errorCount: 0,
    lastError: null,
  };

  constructor() {
  }

  /**
   * Start the scheduler
   */
  start(): void {
    if (this.cronJob) {
      return;
    }

    try {
      this.cronJob = new CronJob(
        appConfig.POLL_CRON,
        this.executePoll.bind(this),
        null,
        true,
        'Europe/Paris'
      );

      this.stats.isRunning = true;
      this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
    } catch (error) {
      this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
    }
  }

  /**
   * Stop the scheduler
   */
  stop(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
      this.stats.isRunning = false;
      this.stats.nextRunTime = null;
    }
  }

  /**
   * Execute polling cycle
   */
  private async executePoll(): Promise<void> {
    const startTime = Date.now();
    this.stats.lastRunTime = new Date();
    this.stats.totalRuns++;

    try {
      // Get all enabled rules
      const rules = this.store.getEnabledRules();
      if (rules.length === 0) {
        return;
      }

      // Process rules in batches to avoid rate limiting while maintaining speed
      const BATCH_SIZE = 10; // Process 10 rules in parallel
      const BATCH_DELAY = 2000; // 2 seconds between batches
      
      let totalNewAlerts = 0;
      
      // Split rules into batches
      for (let batchStart = 0; batchStart < rules.length; batchStart += BATCH_SIZE) {
        const batch = rules.slice(batchStart, batchStart + BATCH_SIZE);
        
        // Process batch in parallel
        const batchPromises = batch.map(async (rule) => {
          if (!rule) return 0;
          
          try {
            return await this.processRule(rule);
          } catch (error) {
            this.stats.errorCount++;
            this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
            return 0;
          }
        });
        
        const batchResults = await Promise.all(batchPromises);
        totalNewAlerts += batchResults.reduce((sum, count) => sum + count, 0);
        
        // Add delay between batches (skip for last batch)
        if (batchStart + BATCH_SIZE < rules.length) {
          await new Promise(resolve => setTimeout(resolve, BATCH_DELAY));
        }
      }

      this.stats.totalAlerts += totalNewAlerts;

      // Update next run time
      if (this.cronJob) {
        this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
      }

    } catch (error) {
      this.stats.errorCount++;
      this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
    }
  }

  /**
   * Process a single rule
   */
  private async processRule(rule: Rule): Promise<number> {
    try {
      const client = getSkinBaronClient();
      
      // Search for items matching the rule
      const response = await client.search({
        search_item: rule.search_item,
        min: rule.min_price || undefined,
        max: rule.max_price || undefined,
        minWear: rule.min_wear || undefined,
        maxWear: rule.max_wear || undefined,
        statTrak: rule.stattrak,
        souvenir: rule.souvenir,
        limit: 20, // Limit to prevent API overload
      });

      if (!response.items || response.items.length === 0) {
        return 0;
      }

      let newAlerts = 0;
      for (const item of response.items) {
        // Check if already processed for this rule
        if (this.store.isProcessed(item.saleId, rule.id)) {
          continue;
        }

        // Double-check filters (API might not be perfect)
        if (!client.matchesFilters(item, {
          search_item: rule.search_item,
          min: rule.min_price,
          max: rule.max_price,
          minWear: rule.min_wear,
          maxWear: rule.max_wear,
          statTrak: rule.stattrak,
          souvenir: rule.souvenir,
        })) {
          continue;
        }

        // Create alert
        try {
          const alert: CreateAlert = {
            rule_id: rule.id!,
            sale_id: item.saleId,
            item_name: item.itemName,
            price: item.price,
            wear_value: item.wearValue,
            stattrak: item.statTrak ?? false,
            souvenir: item.souvenir ?? false,
            skin_url: client.getSkinUrl(item.saleId),
            alert_type: 'match',
          };

          const createdAlert = this.store.createAlert(alert);
          
          // Always count the alert as created, regardless of webhook notifications
          newAlerts++;

          // Get rule webhooks (secured webhook system)
          const webhooks = this.store.getRuleWebhooksForNotification(rule.id!);
          
          // Send notifications to all rule webhooks (if any exist)
          if (webhooks.length > 0) {
            const notificationPromises = webhooks.map(async (webhook: any) => {
              return this.notificationService.sendNotification(
                webhook.webhook_url!,
                {
                  alertType: 'match',
                  item,
                  rule,
                  skinUrl: alert.skin_url,
                }
              );
            });

            // Wait for all notifications to complete
            const results = await Promise.allSettled(notificationPromises);
            
            let successCount = 0;
            results.forEach((result: any) => {
              if (result.status === 'fulfilled' && result.value) {
                successCount++;
              }
            });
          }

        } catch (error) {
          if (error instanceof Error && error.message === 'DUPLICATE_SALE') {
            // Already processed, skip
            continue;
          }
          throw error;
        }
      }

      return newAlerts;

    } catch (error) {
      throw error;
    }
  }

  /**
   * Get scheduler statistics
   */
  getStats(): SchedulerStats {
    if (this.cronJob && this.stats.isRunning) {
      this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
    }
    return { ...this.stats };
  }

  /**
   * Force run a polling cycle (for testing)
   */
  async forceRun(): Promise<void> {
    if (this.stats.isRunning && this.cronJob) {
      await this.executePoll();
    } else {
      throw new Error('Scheduler is not running');
    }
  }

  /**
   * Test a specific rule without creating alerts
   */
  async testRule(rule: Rule): Promise<SkinBaronItem[]> {
    const client = getSkinBaronClient();
    
    const response = await client.search({
      search_item: rule.search_item,
      min: rule.min_price || undefined,
      max: rule.max_price || undefined,
      minWear: rule.min_wear || undefined,
      maxWear: rule.max_wear || undefined,
      statTrak: rule.stattrak,
      souvenir: rule.souvenir,
      limit: 10,
    });

    if (!response.items || response.items.length === 0) {
      return [];
    }

    return response.items.filter((item: SkinBaronItem) => 
      client.matchesFilters(item, {
        search_item: rule.search_item,
        min: rule.min_price || undefined,
        max: rule.max_price || undefined,
        minWear: rule.min_wear || undefined,
        maxWear: rule.max_wear || undefined,
        statTrak: rule.stattrak,
        souvenir: rule.souvenir,
      })
    );
  }

  /**
   * Reset statistics
   */
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

// Singleton instance
let schedulerInstance: AlertScheduler | null = null;

export const getScheduler = (): AlertScheduler => {
  if (!schedulerInstance) {
    schedulerInstance = new AlertScheduler();
  }
  return schedulerInstance;
};

export default getScheduler;