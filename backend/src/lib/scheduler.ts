import { CronJob } from 'cron';
import { appConfig, DISCORD_DELAY_MS, API_PAGE_SIZE } from './config.js';
import { store } from '../database/index.js';
import type { Rule, CreateAlert } from '../database/schemas.js';
import type { Alert, UserWebhook } from '../database/schema.js';
import { getSkinBaronClient, type SkinBaronClient, type SkinBaronItem } from './sbclient.js';
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
  private lastCleanupTime: number = 0; // Track last audit log cleanup by timestamp

  // Concurrency guard — prevents overlapping poll executions
  private polling = false;

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
    // Concurrency guard — skip if a previous poll is still running
    if (this.polling) {
      this.logger.warn({}, '[Scheduler] Skipping poll — previous execution still running');
      return;
    }

    this.polling = true;
    try {
      await this._executePollInner();
    } finally {
      this.polling = false;
    }
  }

  private async _executePollInner(): Promise<void> {
    this.stats.lastRunTime = new Date();
    this.stats.totalRuns++;

    try {
      // Clean old audit logs (GDPR compliance) - run once per day
      const now = Date.now();
      const ONE_DAY_MS = 86_400_000;
      if (now - this.lastCleanupTime >= ONE_DAY_MS) {
        this.lastCleanupTime = now;
        try {
          const result = await store.audit.cleanupOldLogs(appConfig.AUDIT_LOG_RETENTION_DAYS);
          if (result > 0) {
            this.logger.info({ deleted: result, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old audit logs');
          }
        } catch (error) {
          this.logger.error({ error }, '[Scheduler] Failed to clean old audit logs');
        }

        // Clean old admin actions (same retention as audit logs)
        try {
          const result = await store.audit.cleanupOldAdminActions(appConfig.AUDIT_LOG_RETENTION_DAYS);
          if (result > 0) {
            this.logger.info({ deleted: result, retentionDays: appConfig.AUDIT_LOG_RETENTION_DAYS }, '[Scheduler] Cleaned old admin actions');
          }
        } catch (error) {
          this.logger.error({ error }, '[Scheduler] Failed to clean old admin actions');
        }

        // Clean old alerts (GDPR — configurable retention, default 90 days)
        try {
          const result = await store.alerts.cleanupOldAlerts(appConfig.ALERT_RETENTION_DAYS);
          if (result > 0) {
            this.logger.info({ deleted: result, retentionDays: appConfig.ALERT_RETENTION_DAYS }, '[Scheduler] Cleaned old alerts');
          }
        } catch (error) {
          this.logger.error({ error }, '[Scheduler] Failed to clean old alerts');
        }
      }

      // Clean expired blacklisted access tokens periodically (every run)
      try {
        await store.auth.cleanupExpiredBlacklistTokens();
      } catch (error) {
        this.logger.error({ error }, '[Scheduler] Failed to cleanup expired blacklist tokens');
      }

      // Clean expired refresh tokens (every run)
      try {
        await store.auth.cleanupRefreshTokens();
      } catch (error) {
        this.logger.error({ error }, '[Scheduler] Failed to cleanup expired refresh tokens');
      }

      // Clean expired pending challenges (every run)
      try {
        await store.challenges.cleanup();
      } catch (error) {
        this.logger.error({ error }, '[Scheduler] Failed to cleanup expired pending challenges');
      }

      // Get all enabled rules
      const rules = await store.rules.findAllEnabled();
      if (rules.length === 0) {
        return;
      }

      // ── Group rules by search_item to deduplicate API calls ──
      // e.g. 10 rules searching "AK-47" → 1 API call instead of 10
      const ruleGroups = new Map<string, Rule[]>();
      for (const rule of rules) {
        const key = rule.search_item.trim().toLowerCase();
        const group = ruleGroups.get(key) ?? [];
        group.push(rule);
        ruleGroups.set(key, group);
      }

      const groups = Array.from(ruleGroups.values());

      this.logger.info({
        totalRules: rules.length,
        uniqueSearchTerms: groups.length,
        apiCallsSaved: rules.length - groups.length,
      }, '[Scheduler] Grouped rules — deduplicating API calls');

      // Process groups with concurrency control (max N concurrent SkinBaron API calls)
      const API_CONCURRENCY = 3;
      const BATCH_DELAY = 500;
      let totalNewAlerts = 0;

      for (let i = 0; i < groups.length; i += API_CONCURRENCY) {
        const batch = groups.slice(i, i + API_CONCURRENCY);
        const results = await Promise.all(
          batch.map(group => this.processRuleGroup(group).catch((error: unknown) => {
            this.stats.errorCount++;
            this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
            this.logger.error({ error: String(error), searchItem: group[0]?.search_item }, '[Scheduler] Rule group failed');
            return 0;
          }))
        );
        totalNewAlerts += results.reduce((sum, n) => sum + n, 0);

        // Delay between batches to respect SkinBaron rate limits
        if (i + API_CONCURRENCY < groups.length) {
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
   * Merge search params across rules sharing the same search_item.
   * Produces the broadest API call that covers all rules in the group.
   */
  private mergeSearchParams(rules: Rule[]): {
    search_item: string; min?: number; max?: number;
    minWear?: number; maxWear?: number;
    statTrak?: boolean; souvenir?: boolean; limit: number;
  } {
    let minPrice: number | undefined;
    let maxPrice: number | undefined;
    let minWear: number | undefined;
    let maxWear: number | undefined;
    let anyNoMin = false, anyNoMax = false;
    let anyNoMinWear = false, anyNoMaxWear = false;

    for (const rule of rules) {
      if (rule.min_price == null) anyNoMin = true;
      else minPrice = minPrice !== undefined ? Math.min(minPrice, rule.min_price) : rule.min_price;

      if (rule.max_price == null) anyNoMax = true;
      else maxPrice = maxPrice !== undefined ? Math.max(maxPrice, rule.max_price) : rule.max_price;

      if (rule.min_wear == null) anyNoMinWear = true;
      else minWear = minWear !== undefined ? Math.min(minWear, rule.min_wear) : rule.min_wear;

      if (rule.max_wear == null) anyNoMaxWear = true;
      else maxWear = maxWear !== undefined ? Math.max(maxWear, rule.max_wear) : rule.max_wear;
    }

    // Only apply statTrak/souvenir API filter if ALL rules in the group agree
    const statTrakFilters = new Set(rules.map(r => r.stattrak_filter));
    const souvenirFilters = new Set(rules.map(r => r.souvenir_filter));

    const firstRule = rules[0];
    if (!firstRule) throw new Error('Empty rules group');

    return {
      search_item: firstRule.search_item,
      min: anyNoMin ? undefined : minPrice,
      max: anyNoMax ? undefined : maxPrice,
      minWear: anyNoMinWear ? undefined : minWear,
      maxWear: anyNoMaxWear ? undefined : maxWear,
      statTrak: statTrakFilters.size === 1 && statTrakFilters.has('only') ? true
             : statTrakFilters.size === 1 && statTrakFilters.has('exclude') ? false
             : undefined,
      souvenir: souvenirFilters.size === 1 && souvenirFilters.has('only') ? true
             : souvenirFilters.size === 1 && souvenirFilters.has('exclude') ? false
             : undefined,
      limit: API_PAGE_SIZE,
    };
  }

  /**
   * Process a group of rules sharing the same search_item with a single API call.
   */
  private async processRuleGroup(rules: Rule[]): Promise<number> {
    const client = getSkinBaronClient();
    const params = this.mergeSearchParams(rules);

    const response = await client.search(params);
    const allItems = response.items ?? [];
    const hitPageLimit = allItems.length >= API_PAGE_SIZE;

    this.logger.info({
      searchItem: params.search_item,
      rulesInGroup: rules.length,
      foundItems: allItems.length,
    }, '[Scheduler] API response for rule group');

    // No items at all — clean up stale alerts for all rules in the group
    if (allItems.length === 0) {
      for (const rule of rules) {
        if (!rule.id) continue;
        const existing = await store.alerts.findSaleIdPricesByRuleId(rule.id);
        if (existing.length > 0) {
          await store.alerts.deleteBySaleIdsForRule(existing.map(p => p.sale_id), rule.id);
          this.logger.info({ ruleId: rule.id, deletedCount: existing.length }, '[Scheduler] Cleaned stale alerts — no items found');
        }
      }
      return 0;
    }

    // Pre-compute the set of all sale_ids from the API (shared across rules in the group)
    const allApiSaleIds = new Set(allItems.map(item => item.saleId));

    let totalNewAlerts = 0;
    for (const rule of rules) {
      try {
        totalNewAlerts += await this.processRuleWithItems(rule, allItems, allApiSaleIds, client, hitPageLimit);
      } catch (error) {
        this.stats.errorCount++;
        this.stats.lastError = error instanceof Error ? error.message : 'Unknown error';
        this.logger.error({ error, ruleId: rule.id }, '[Scheduler] Rule processing failed');
      }
    }
    return totalNewAlerts;
  }

  /**
   * Process a single rule against pre-fetched items from a shared API call.
   * Applies per-rule filters, detects new items & price changes, creates alerts.
   */
  private async processRuleWithItems(
    rule: Rule,
    allItems: SkinBaronItem[],
    allApiSaleIds: Set<string>,
    client: SkinBaronClient,
    hitPageLimit: boolean
  ): Promise<number> {
    if (!rule.id) return 0;
    const ruleId = rule.id;

    // ── Per-rule local filtering on the shared item set ──
    const items = allItems.filter(item => {
      if (rule.min_price != null && item.price < rule.min_price) return false;
      if (rule.max_price != null && item.price > rule.max_price) return false;

      if (rule.min_wear != null) {
        if (item.wearValue !== undefined && item.wearValue < rule.min_wear) return false;
      }
      if (rule.max_wear != null) {
        if (item.wearValue !== undefined && item.wearValue > rule.max_wear) return false;
      }

      const isStatTrak = item.statTrak || item.itemName.includes('StatTrak\u2122');
      if (rule.stattrak_filter === 'only' && !isStatTrak) return false;
      if (rule.stattrak_filter === 'exclude' && isStatTrak) return false;

      const isSouvenir = item.souvenir || item.itemName.includes('Souvenir');
      if (rule.souvenir_filter === 'only' && !isSouvenir) return false;
      if (rule.souvenir_filter === 'exclude' && isSouvenir) return false;

      if (rule.sticker_filter === 'only' && !item.hasStickers) return false;
      if (rule.sticker_filter === 'exclude' && item.hasStickers) return false;

      return true;
    });

    // ── Lightweight existing alerts lookup (sale_id + price only, not full rows) ──
    const existingPairs = await store.alerts.findSaleIdPricesByRuleId(ruleId);
    const existingMap = new Map(existingPairs.map(p => [p.sale_id, p.price]));

    // ── Delete stale alerts ──
    // Two cases:
    //   1. Item sold/removed from SkinBaron (only when we have full result set)
    //   2. Item still on SkinBaron but no longer matches rule criteria
    //      (e.g. max_price lowered from 10€ to 7€ → remove alerts at 9€)
    const filteredSaleIds = new Set(items.map(item => item.saleId));
    let obsoleteRemoved = 0;
    if (existingPairs.length > 0) {
      const staleSaleIds = existingPairs.filter(p => {
        if (!hitPageLimit) {
          // Full result set: remove if item is gone OR no longer matches rule
          return !filteredSaleIds.has(p.sale_id);
        }
        // Paginated: only remove items we SAW in the API but that didn't pass the filter
        return allApiSaleIds.has(p.sale_id) && !filteredSaleIds.has(p.sale_id);
      }).map(p => p.sale_id);
      if (staleSaleIds.length > 0) {
        obsoleteRemoved = await store.alerts.deleteBySaleIdsForRule(staleSaleIds, ruleId);
      }
    }

    // ── Process matched items — detect new items and price changes ──
    let newAlerts = 0;
    let skippedExisting = 0;
    let priceChanges = 0;
    const matchingItems: SkinBaronItem[] = [];

    for (const item of items) {
      const existingPrice = existingMap.get(item.saleId);

      if (existingPrice !== undefined) {
        if (existingPrice === item.price) {
          skippedExisting++;
          continue;
        }
        // Price changed — remove old alert so it gets recreated below
        await store.alerts.deleteBySaleIdAndRuleId(item.saleId, ruleId);
        priceChanges++;
      }

      matchingItems.push(item);
    }

    // ── Batch insert new alerts (notified_at defaults to NULL) ──
    if (matchingItems.length > 0) {
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

      const insertedCount = await store.alerts.createBatch(alertsToCreate);
      newAlerts = insertedCount;
    }

    // ── Send notifications for ALL un-notified alerts (catches new + missed from previous runs/restarts) ──
    const webhooks = await store.webhooks.getRuleWebhooksForNotification(ruleId);
    if (webhooks.length > 0) {
      const unnotifiedAlerts = await store.alerts.findUnnotifiedByRuleId(ruleId);
      if (unnotifiedAlerts.length > 0) {
        await this.sendAndMarkNotifications(unnotifiedAlerts, webhooks, rule, client);
      }
    }

    this.logger.info({
      ruleId,
      searchItem: rule.search_item,
      apiItems: allItems.length,
      filteredItems: items.length,
      skippedExisting,
      newAlerts,
      priceChanges,
      obsoleteRemoved,
    }, '[Scheduler] Rule processing completed');

    return newAlerts;
  }

  /**
   * Send Discord notifications for a batch of un-notified alerts, then mark them as notified.
   * Respects Discord rate limits with sequential sending per webhook.
   */
  private async sendAndMarkNotifications(
    unnotifiedAlerts: Alert[],
    webhooks: UserWebhook[],
    rule: Rule,
    client: SkinBaronClient,
  ): Promise<void> {
    const notifiedIds: number[] = [];

    for (const alert of unnotifiedAlerts) {
      // Always compute offer URL from saleId — skin_url stores the Steam CDN image
      const offerUrl = client.getSkinUrl(alert.sale_id, alert.item_name);
      const item: SkinBaronItem = {
        saleId: alert.sale_id,
        itemName: alert.item_name,
        price: alert.price,
        wearValue: alert.wear_value ?? undefined,
        statTrak: alert.stattrak,
        souvenir: alert.souvenir,
        hasStickers: alert.has_stickers,
        imageUrl: alert.skin_url, // Steam CDN image for embed thumbnail
        skinUrl: offerUrl,        // SkinBaron offer URL for links
      };

      let anySent = false;
      for (const webhook of webhooks) {
        if (!webhook.webhook_url) continue;
        try {
          const success = await this.notificationService.sendNotification(webhook.webhook_url, {
            item, rule, skinUrl: offerUrl,
            style: (webhook.notification_style as NotificationStyle) || 'compact',
          });
          if (success) anySent = true;
          else {
            this.logger.warn({
              webhookUrl: webhook.webhook_url.substring(0, 50) + '...',
              item: alert.item_name,
            }, '[Scheduler] Webhook notification failed to send');
          }
        } catch (error) {
          this.logger.error({
            error: error instanceof Error ? error.message : error,
            item: alert.item_name,
          }, '[Scheduler] Webhook notification threw error');
        }
        // Delay between messages per webhook to respect Discord rate limits
        await new Promise(resolve => setTimeout(resolve, DISCORD_DELAY_MS));
      }

      // Mark as notified if at least one webhook succeeded (avoid infinite retry on permanently broken webhooks)
      if (anySent) {
        notifiedIds.push(alert.id);
      }
    }

    // Batch-update notified_at for all successfully sent alerts
    if (notifiedIds.length > 0) {
      await store.alerts.markNotified(notifiedIds);
      this.logger.info({ ruleId: rule.id, notified: notifiedIds.length, total: unnotifiedAlerts.length }, '[Scheduler] Marked alerts as notified');
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
      min: rule.min_price ?? undefined,
      max: rule.max_price ?? undefined,
      minWear: rule.min_wear ?? undefined,
      maxWear: rule.max_wear ?? undefined,
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
        min: rule.min_price ?? undefined,
        max: rule.max_price ?? undefined,
        minWear: rule.min_wear ?? undefined,
        maxWear: rule.max_wear ?? undefined,
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