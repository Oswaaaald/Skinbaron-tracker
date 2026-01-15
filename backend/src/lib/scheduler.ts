import { CronJob } from 'cron';
import { appConfig } from './config.js';
import { getStore, type Rule, type CreateAlert } from './store.js';
import { getSkinBaronClient, type SkinBaronItem } from './sbclient.js';
import { getNotificationService } from './notifier.js';
import pino, { type Logger } from 'pino';
import { type FastifyBaseLogger } from 'fastify';

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
  private logger: Logger | FastifyBaseLogger = pino({ level: appConfig.LOG_LEVEL });
  private cronJob: CronJob | null = null;
  private store = getStore();
  private notificationService = getNotificationService();

  // Discord rate limiting: max 30 messages per minute per webhook
  private readonly DISCORD_DELAY_MS = 2100; // ~2 seconds between messages (allows ~28 per minute with safety margin)
  private webhookQueues = new Map<string, Promise<void>>();

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

  setLogger(logger: Logger | FastifyBaseLogger) {
    this.logger = logger;
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
   * Force immediate execution (bypass cron schedule)
   */
  async forceRun(): Promise<void> {
    await this.executePoll();
  }

  /**
   * Execute polling cycle
   */
  private async executePoll(): Promise<void> {
    this.stats.lastRunTime = new Date();
    this.stats.totalRuns++;

    try {
      // Clean old audit logs (GDPR compliance) - run once per day
      if (this.stats.totalRuns % 288 === 1) { // Every 288 runs at 5min intervals = ~1 day
        try {
          const result = this.store.cleanOldAuditLogs(appConfig.AUDIT_LOG_RETENTION_DAYS);
          if (result.deleted > 0) {
            this.logger.info({ deleted: result.deleted, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old audit logs');
          }
        } catch (error) {
          this.logger.error({ error }, '[Scheduler] Failed to clean old audit logs');
        }
      }

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
      
      // Convert filter enums to boolean params for API
      // 'only' = true, 'exclude' = false, 'all' = undefined (no filter)
      const statTrakParam = rule.stattrak_filter === 'only' ? true : 
                           rule.stattrak_filter === 'exclude' ? false : undefined;
      const souvenirParam = rule.souvenir_filter === 'only' ? true : 
                           rule.souvenir_filter === 'exclude' ? false : undefined;
      
      // Search for items matching the rule
      const response = await client.search({
        search_item: rule.search_item,
        min: rule.min_price || undefined,
        max: rule.max_price || undefined,
        minWear: rule.min_wear || undefined,
        maxWear: rule.max_wear || undefined,
        statTrak: statTrakParam,
        souvenir: souvenirParam,
        limit: 1000, // High limit to catch all matching items
      });

      if (!response.items || response.items.length === 0) {
        this.logger.info({ ruleId: rule.id, searchItem: rule.search_item }, '[Scheduler] No items found from API');
        return 0;
      }

      this.logger.info({ 
        ruleId: rule.id, 
        searchItem: rule.search_item, 
        foundItems: response.items.length 
      }, '[Scheduler] Items found from API');

      let newAlerts = 0;
      let skippedAlreadyProcessed = 0;
      let skippedByFilters = 0;
      
      // Collect all matching items first, then batch create alerts
      const matchingItems: typeof response.items = [];
      
      for (const item of response.items) {
        // Check if already processed for this rule
        if (this.store.isProcessed(item.saleId, rule.id)) {
          skippedAlreadyProcessed++;
          continue;
        }

        // Apply additional filters that the API might not handle perfectly
        // Filter StatTrak based on rule
        const itemIsStatTrak = item.statTrak || item.itemName.includes('StatTrak™');
        if (rule.stattrak_filter === 'only' && !itemIsStatTrak) {
          skippedByFilters++;
          continue;
        }
        if (rule.stattrak_filter === 'exclude' && itemIsStatTrak) {
          skippedByFilters++;
          continue;
        }

        // Filter Souvenir based on rule
        const itemIsSouvenir = item.souvenir || item.itemName.includes('Souvenir');
        if (rule.souvenir_filter === 'only' && !itemIsSouvenir) {
          skippedByFilters++;
          continue;
        }
        if (rule.souvenir_filter === 'exclude' && itemIsSouvenir) {
          skippedByFilters++;
          continue;
        }

        // Filter stickers - check if item HAS stickers applied
        // allow_stickers = true means accept items with stickers
        // allow_stickers = false means reject items with stickers
        if (!rule.allow_stickers && item.hasStickers) {
          skippedByFilters++;
          continue; // Skip items with stickers if not allowed
        }

        // Double-check basic filters (API might not be perfect)
        if (!client.matchesFilters(item, {
          search_item: rule.search_item,
          min: rule.min_price,
          max: rule.max_price,
          minWear: rule.min_wear,
          maxWear: rule.max_wear,
          statTrak: statTrakParam,
          souvenir: souvenirParam,
        })) {
          skippedByFilters++;
          continue;
        }

        // Item passed all filters, add to matching items
        matchingItems.push(item);
      }

      // Batch create alerts and send notifications
      if (matchingItems.length > 0) {
        // Get webhooks once for the rule
        const webhooks = this.store.getRuleWebhooksForNotification(rule.id!);
        
        // Prepare all alerts for batch insert
        const alertsToCreate: CreateAlert[] = matchingItems.map(item => ({
          rule_id: rule.id!,
          sale_id: item.saleId,
          item_name: item.itemName,
          price: item.price,
          wear_value: item.wearValue,
          stattrak: item.statTrak ?? false,
          souvenir: item.souvenir ?? false,
          skin_url: item.imageUrl || item.skinUrl || client.getSkinUrl(item.saleId),
          alert_type: 'match',
        }));

        // Batch insert all alerts at once (much faster!)
        const insertedCount = this.store.createAlertsBatch(alertsToCreate);
        newAlerts += insertedCount;

        // Send notifications if webhooks exist (async, don't block)
        if (webhooks.length > 0) {
          for (const item of matchingItems) {
            const offerUrl = item.skinUrl || client.getSkinUrl(item.saleId);
            
            for (const webhook of webhooks) {
              this.queueWebhookNotification(
                webhook.webhook_url!,
                {
                  alertType: 'match',
                  item,
                  rule,
                  skinUrl: offerUrl,
                }
              ).catch((error) => {
                this.logger.warn({ 
                  error: error instanceof Error ? error.message : 'Unknown error',
                  webhookId: webhook.id,
                  ruleId: rule.id,
                  itemName: item.itemName 
                }, 'Failed to send webhook notification');
              });
            }
          }
        }
      }

      // Log filtering summary
      this.logger.info({
        ruleId: rule.id,
        searchItem: rule.search_item,
        totalFound: response.items.length,
        skippedAlreadyProcessed,
        skippedByFilters,
        newAlerts
      }, '[Scheduler] Rule processing completed');

      return newAlerts;

    } catch (error) {
      throw error;
    }
  }

  /**
   * Queue webhook notification with rate limiting per webhook URL
   * Discord allows max 30 messages per minute per webhook
   */
  private async queueWebhookNotification(
    webhookUrl: string,
    options: { alertType: 'match' | 'best_deal' | 'new_item', item: SkinBaronItem, rule?: Rule, skinUrl: string }
  ): Promise<void> {
    // Get or create queue for this webhook URL
    const existingQueue = this.webhookQueues.get(webhookUrl) || Promise.resolve();
    
    // Chain the new notification after the existing queue
    const newQueue = existingQueue.then(async () => {
      try {
        await this.notificationService.sendNotification(webhookUrl, options);
      } catch (error) {
        // Log but don't throw - we don't want to block other notifications
      }
      // Add delay before next message to respect Discord rate limits
      await new Promise(resolve => setTimeout(resolve, this.DISCORD_DELAY_MS));
    });
    
    // Update the queue
    this.webhookQueues.set(webhookUrl, newQueue);
    
    // Clean up the queue after it's done (with extra time buffer)
    newQueue.then(() => {
      setTimeout(() => {
        if (this.webhookQueues.get(webhookUrl) === newQueue) {
          this.webhookQueues.delete(webhookUrl);
        }
      }, this.DISCORD_DELAY_MS * 2);
    });
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
   * Test a specific rule without creating alerts
   */
  async testRule(rule: Rule): Promise<SkinBaronItem[]> {
    const client = getSkinBaronClient();
    
    // Convert filter enums to boolean params for API
    const statTrakParam = rule.stattrak_filter === 'only' ? true : 
                         rule.stattrak_filter === 'exclude' ? false : undefined;
    const souvenirParam = rule.souvenir_filter === 'only' ? true : 
                         rule.souvenir_filter === 'exclude' ? false : undefined;
    
    const response = await client.search({
      search_item: rule.search_item,
      min: rule.min_price || undefined,
      max: rule.max_price || undefined,
      minWear: rule.min_wear || undefined,
      maxWear: rule.max_wear || undefined,
      statTrak: statTrakParam,
      souvenir: souvenirParam,
      limit: 10,
    });

    if (!response.items || response.items.length === 0) {
      return [];
    }

    return response.items.filter((item: SkinBaronItem) => {
      // Apply all filters including the new ones
      const itemIsStatTrak = item.statTrak || item.itemName.includes('StatTrak™');
      if (rule.stattrak_filter === 'only' && !itemIsStatTrak) return false;
      if (rule.stattrak_filter === 'exclude' && itemIsStatTrak) return false;

      const itemIsSouvenir = item.souvenir || item.itemName.includes('Souvenir');
      if (rule.souvenir_filter === 'only' && !itemIsSouvenir) return false;
      if (rule.souvenir_filter === 'exclude' && itemIsSouvenir) return false;

      // Filter stickers - check if item HAS stickers applied
      if (!rule.allow_stickers && item.hasStickers) {
        return false;
      }

      return client.matchesFilters(item, {
        search_item: rule.search_item,
        min: rule.min_price || undefined,
        max: rule.max_price || undefined,
        minWear: rule.min_wear || undefined,
        maxWear: rule.max_wear || undefined,
        statTrak: statTrakParam,
        souvenir: souvenirParam,
      });
    });
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