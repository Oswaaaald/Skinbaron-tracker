import { CronJob } from 'cron';
import { appConfig } from './config.js';
import { store } from '../database/index.js';
import type { Rule, CreateAlert } from '../database/schemas.js';
import { getSkinBaronClient, type SkinBaronItem } from './sbclient.js';
import { getNotificationService, type NotificationStyle } from './notifier.js';
import pino from 'pino';

// Logger interface compatible with both pino.Logger and FastifyBaseLogger
interface SchedulerLogger {
  info(obj: object, msg?: string): void;
  error(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
  debug(obj: object, msg?: string): void;
}

interface SchedulerStats {
  isRunning: boolean;
  lastRunTime: Date | null;
  nextRunTime: Date | null;
  totalRuns: number;
  totalAlerts: number;
  errorCount: number;
  lastError: string | null;
}

export class AlertScheduler {
  private logger: SchedulerLogger = pino({ level: appConfig.LOG_LEVEL });
  private cronJob: CronJob | null = null;
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

  setLogger(logger: SchedulerLogger) {
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
        () => {
          void this.executePoll();
        },
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
      void this.cronJob.stop();
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
          const result = store.cleanOldAuditLogs(appConfig.AUDIT_LOG_RETENTION_DAYS);
          if (result > 0) {
            this.logger.info({ deleted: result, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old audit logs');
          }
        } catch (error) {
          this.logger.error({ error }, '[Scheduler] Failed to clean old audit logs');
        }
      }

      // Get all enabled rules
      const rules = store.getEnabledRules();
      if (rules.length === 0) {
        return;
      }

      // Process rules in batches to avoid rate limiting while maintaining speed
      const BATCH_SIZE = 10; // Process 10 rules in parallel
      const BATCH_DELAY = 1000; // 1 second between batches
      
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

      // Get existing alerts for this rule to track changes
      const existingAlerts = rule.id ? store.findAlertsByRuleId(rule.id) : [];
      const existingAlertsMap = new Map(existingAlerts.map(alert => [alert.sale_id, alert]));

      if (!response.items || response.items.length === 0) {
        // No items found - delete all existing alerts for this rule as offers are gone
        if (existingAlerts.length > 0 && rule.id) {
          const saleIdsToDelete = existingAlerts.map(a => a.sale_id);
          const deletedCount = store.deleteBySaleIds(saleIdsToDelete);
          if (deletedCount > 0) {
            this.logger.info({ 
              ruleId: rule.id, 
              searchItem: rule.search_item, 
              deletedCount 
            }, '[Scheduler] Deleted alerts for sold/removed offers');
          }
        }
        return 0;
      }

      this.logger.info({ 
        ruleId: rule.id, 
        searchItem: rule.search_item, 
        foundItems: response.items.length 
      }, '[Scheduler] Items found from API');

      // Track current sale_ids from API to detect removed offers
      const currentSaleIds = new Set(response.items.map(item => item.saleId));
      
      // Delete alerts for offers that no longer exist
      const obsoleteSaleIds = existingAlerts
        .map(alert => alert.sale_id)
        .filter(saleId => !currentSaleIds.has(saleId));
      
      if (obsoleteSaleIds.length > 0) {
        const deletedCount = store.deleteBySaleIds(obsoleteSaleIds);
        this.logger.info({ 
          ruleId: rule.id, 
          obsoleteCount: deletedCount 
        }, '[Scheduler] Deleted alerts for sold/removed offers');
      }

      let newAlerts = 0;
      let skippedAlreadyProcessed = 0;
      let skippedByFilters = 0;
      let priceChanges = 0;
      
      // Batch check for already processed items to avoid N+1 queries
      const saleIds = response.items.map(item => item.saleId);
      const processedAlerts = store.alerts.findBySaleIds(saleIds);
      const processedSet = new Set(processedAlerts.map(alert => alert.sale_id));
      
      // Collect all matching items first, then batch create alerts
      const matchingItems: typeof response.items = [];
      
      for (const item of response.items) {
        // Check if already processed for this rule (using batched data)
        if (processedSet.has(item.saleId)) {
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

        // Filter stickers
        if (rule.sticker_filter === 'only' && !item.hasStickers) {
          skippedByFilters++;
          continue;
        }
        if (rule.sticker_filter === 'exclude' && item.hasStickers) {
          skippedByFilters++;
          continue;
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

        // Check if this item already has an alert with different price
        const existingAlert = existingAlertsMap.get(item.saleId);
        if (existingAlert && existingAlert.price !== item.price) {
          // Price changed - delete old alert and recreate with new price
          if (rule.id) {
            store.deleteBySaleIdAndRuleId(item.saleId, rule.id);
            priceChanges++;
            this.logger.debug({ 
              saleId: item.saleId, 
              oldPrice: existingAlert.price, 
              newPrice: item.price 
            }, '[Scheduler] Price changed, recreating alert');
          }
          // Remove from map so it will be recreated
          existingAlertsMap.delete(item.saleId);
        }

        // Item passed all filters, add to matching items (skip if already alerted with same price)
        if (!existingAlert || existingAlert.price !== item.price) {
          matchingItems.push(item);
        }
      }

      // Batch create alerts and send notifications
      if (matchingItems.length > 0 && rule.id !== undefined) {
        // Get webhooks once for the rule
        const webhooks = store.getRuleWebhooksForNotification(rule.id);
        
        // Prepare all alerts for batch insert
        const ruleId = rule.id;
        const alertsToCreate: CreateAlert[] = matchingItems.map(item => ({
          rule_id: ruleId,
          sale_id: item.saleId,
          item_name: item.itemName,
          price: item.price,
          wear_value: item.wearValue,
          stattrak: item.statTrak ?? false,
          souvenir: item.souvenir ?? false,
          has_stickers: item.hasStickers ?? false,
          skin_url: item.imageUrl || item.skinUrl || client.getSkinUrl(item.saleId),
        }));

        // Batch insert all alerts at once (much faster!)
        const insertedCount = store.createAlertsBatch(alertsToCreate);
        newAlerts += insertedCount;

        // Send notifications if webhooks exist (async, don't block)
        if (webhooks.length > 0) {
          for (const item of matchingItems) {
            const offerUrl = item.skinUrl || client.getSkinUrl(item.saleId);
            
            for (const webhook of webhooks) {
              if (webhook.webhook_url) {
                this.queueWebhookNotification(
                  webhook.webhook_url,
                  {
                    item,
                    rule,
                    skinUrl: offerUrl,
                    style: (webhook.notification_style as NotificationStyle) || 'compact',
                  }
                );
              }
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
        newAlerts,
        priceChanges,
        obsoleteRemoved: obsoleteSaleIds.length
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
  private queueWebhookNotification(
    webhookUrl: string,
    options: { item: SkinBaronItem, rule?: Rule, skinUrl: string, style?: NotificationStyle }
  ): void {
    // Get or create queue for this webhook URL
    const existingQueue = this.webhookQueues.get(webhookUrl) || Promise.resolve();
    
    // Chain the new notification after the existing queue
    const newQueue = existingQueue.then(async () => {
      try {
        await this.notificationService.sendNotification(webhookUrl, options);
      } catch {
        // Log but don't throw - we don't want to block other notifications
      }
      // Add delay before next message to respect Discord rate limits
      await new Promise(resolve => setTimeout(resolve, this.DISCORD_DELAY_MS));
    });
    
    // Update the queue
    this.webhookQueues.set(webhookUrl, newQueue);
    
    // Clean up the queue after it's done (with extra time buffer)
    void newQueue.then(() => {
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

      // Filter stickers
      if (rule.sticker_filter === 'only' && !item.hasStickers) return false;
      if (rule.sticker_filter === 'exclude' && item.hasStickers) return false;

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