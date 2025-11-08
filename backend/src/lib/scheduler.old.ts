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
      console.error('❌ Failed to start scheduler:', error);
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
      console.log('🛑 Scheduler stopped');
    }
  }

  /**
   * Execute polling cycle
   */
  private async executePoll(): Promise<void> {
    const startTime = Date.now();
    this.stats.lastRunTime = new Date();
    this.stats.totalRuns++;

    console.log(`🔄 Starting polling cycle #${this.stats.totalRuns}...`);

    try {
      // Get all enabled rules
      const rules = this.store.getEnabledRules();
      if (rules.length === 0) {
        console.log('ℹ️  No enabled rules found, skipping poll');
        return;
      }

      console.log(`📋 Processing ${rules.length} active rules`);

      // Process each rule
      let newAlerts = 0;
      for (const rule of rules) {
        try {
          const ruleAlerts = await this.processRule(rule);
          newAlerts += ruleAlerts;
        } catch (error) {
          console.error(`❌ Error processing rule ${rule.id}:`, error);
          this.stats.errorCount++;
          this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
        }
      }

      // Only process user-defined rules (no automatic feeds)

      this.stats.totalAlerts += newAlerts;
      const duration = Date.now() - startTime;

      console.log(`✅ Polling cycle completed in ${duration}ms`);
      console.log(`📊 New alerts: ${newAlerts} | Total alerts: ${this.stats.totalAlerts}`);

      // Update next run time
      if (this.cronJob) {
        this.stats.nextRunTime = this.cronJob.nextDate().toJSDate();
      }

    } catch (error) {
      console.error('❌ Polling cycle failed:', error);
      this.stats.errorCount++;
      this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
    }
  }

  /**
   * Process a single rule
   */
  private async processRule(rule: Rule): Promise<number> {
    console.log(`🎯 Processing rule: "${rule.search_item}" (ID: ${rule.id})`);

    try {
      // Search for items matching the rule
      const response = await this.skinBaronClient.search({
        search_item: rule.search_item,
        min: rule.min_price,
        max: rule.max_price,
        minWear: rule.min_wear,
        maxWear: rule.max_wear,
        statTrak: rule.stattrak,
        souvenir: rule.souvenir,
        limit: 20, // Limit to prevent API overload
      });

      if (!response.success || !response.items) {
        console.log(`⚠️  No items found for rule ${rule.id}`);
        return 0;
      }

      let newAlerts = 0;
      for (const item of response.items) {
        // Check if already processed
        if (this.store.isProcessed(item.saleId)) {
          continue;
        }

        // Double-check filters (API might not be perfect)
        if (!this.skinBaronClient.matchesFilters(item, {
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
            skin_url: this.skinBaronClient.getSkinUrl(item.saleId),
            alert_type: 'match',
          };

          const createdAlert = this.store.createAlert(alert);

          // Get rule webhooks (new system)
          const webhooks = this.store.getRuleWebhooksForNotification(rule.id!);
          
          console.log(`🔔 Rule ${rule.id} notification debug:`, {
            ruleId: rule.id,
            ruleWebhookIds: rule.webhook_ids,
            foundWebhooks: webhooks.length,
            webhookDetails: webhooks.map(w => ({ id: w.id, name: w.name, hasUrl: !!w.webhook_url }))
          });
          
          // Send notifications to all rule webhooks
          const notificationPromises = webhooks.map(async (webhook) => {
            console.log(`📤 Sending notification via webhook ${webhook.id} (${webhook.name})`);
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
          results.forEach((result, index) => {
            if (result.status === 'fulfilled' && result.value) {
              successCount++;
            } else {
              console.error(`❌ Failed to send notification to webhook ${webhooks[index]?.name || 'unknown'}:`, 
                result.status === 'rejected' ? result.reason : 'Unknown error');
            }
          });

          if (successCount > 0) {
            newAlerts++;
            console.log(`✅ Alert sent for: ${item.itemName} (${item.price} EUR) to ${successCount}/${webhooks.length} webhooks`);
          } else {
            console.error(`❌ Failed to send notification for alert ${createdAlert.id} to any webhook`);
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
      console.error(`❌ Failed to process rule ${rule.id}:`, error);
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
      console.log('🔄 Force running polling cycle...');
      await this.executePoll();
    } else {
      throw new Error('Scheduler is not running');
    }
  }

  /**
   * Test a specific rule without creating alerts
   */
  async testRule(rule: Rule): Promise<SkinBaronItem[]> {
    console.log(`🧪 Testing rule: "${rule.search_item}"`);

    const response = await this.skinBaronClient.search({
      search_item: rule.search_item,
      min: rule.min_price,
      max: rule.max_price,
      minWear: rule.min_wear,
      maxWear: rule.max_wear,
      statTrak: rule.stattrak,
      souvenir: rule.souvenir,
      limit: 10,
    });

    if (!response.success || !response.items) {
      return [];
    }

    return response.items.filter(item => 
      this.skinBaronClient.matchesFilters(item, {
        search_item: rule.search_item,
        min: rule.min_price,
        max: rule.max_price,
        minWear: rule.min_wear,
        maxWear: rule.max_wear,
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
    console.log('📊 Scheduler statistics reset');
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