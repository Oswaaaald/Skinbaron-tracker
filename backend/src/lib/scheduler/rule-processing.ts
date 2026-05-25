import { DISCORD_DELAY_MS, API_PAGE_SIZE } from '../config.js';
import { store } from '../../database/index.js';
import type { Rule, CreateAlert } from '../../database/validation-schemas.js';
import type { Alert, UserWebhook } from '../../database/schema.js';
import { getSkinBaronClient, type SkinBaronClient, type SkinBaronItem } from '../sbclient.js';
import { getNotificationService } from '../notifier.js';
import type { SchedulerLogger } from './types.js';

function filterItemsByRule(items: SkinBaronItem[], rule: Rule): SkinBaronItem[] {
  return items.filter(item => {
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
}

export function mergeSearchParams(rules: Rule[]): {
  search_item: string;
  min?: number;
  max?: number;
  minWear?: number;
  maxWear?: number;
  statTrak?: boolean;
  souvenir?: boolean;
  limit: number;
} {
  let minPrice: number | undefined;
  let maxPrice: number | undefined;
  let minWear: number | undefined;
  let maxWear: number | undefined;
  let anyNoMin = false;
  let anyNoMax = false;
  let anyNoMinWear = false;
  let anyNoMaxWear = false;

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

type ProcessRuleGroupDeps = {
  logger: SchedulerLogger;
  notificationService: ReturnType<typeof getNotificationService>;
  onError: (error: unknown) => void;
};

export async function processRuleGroup(rules: Rule[], deps: ProcessRuleGroupDeps): Promise<number> {
  const client = getSkinBaronClient();
  const params = mergeSearchParams(rules);

  const response = await client.search(params);
  const allItems = response.items ?? [];
  const hitPageLimit = allItems.length >= API_PAGE_SIZE;

  deps.logger.info({
    searchItem: params.search_item,
    rulesInGroup: rules.length,
    foundItems: allItems.length,
  }, '[Scheduler] API response for rule group');

  if (allItems.length === 0) {
    for (const rule of rules) {
      if (!rule.id) continue;
      const existing = await store.alerts.findSaleIdPricesByRuleId(rule.id);
      if (existing.length > 0) {
        await store.alerts.deleteBySaleIdsForRule(existing.map(p => p.sale_id), rule.id);
        deps.logger.info({ ruleId: rule.id, deletedCount: existing.length }, '[Scheduler] Cleaned stale alerts — no items found');
      }
    }
    return 0;
  }

  const allApiSaleIds = new Set(allItems.map(item => item.saleId));

  let totalNewAlerts = 0;
  for (const rule of rules) {
    try {
      totalNewAlerts += await processRuleWithItems(rule, allItems, allApiSaleIds, hitPageLimit, client, deps);
    } catch (error) {
      deps.onError(error);
      deps.logger.error({ error, ruleId: rule.id }, '[Scheduler] Rule processing failed');
    }
  }

  return totalNewAlerts;
}

async function processRuleWithItems(
  rule: Rule,
  allItems: SkinBaronItem[],
  allApiSaleIds: Set<string>,
  hitPageLimit: boolean,
  client: SkinBaronClient,
  deps: ProcessRuleGroupDeps,
): Promise<number> {
  if (!rule.id) return 0;
  const ruleId = rule.id;

  const items = filterItemsByRule(allItems, rule);

  const existingPairs = await store.alerts.findSaleIdPricesByRuleId(ruleId);
  const existingMap = new Map(existingPairs.map(p => [p.sale_id, p.price]));

  const filteredSaleIds = new Set(items.map(item => item.saleId));
  let obsoleteRemoved = 0;
  if (existingPairs.length > 0) {
    const staleSaleIds = existingPairs.filter(p => {
      if (!hitPageLimit) {
        return !filteredSaleIds.has(p.sale_id);
      }
      return allApiSaleIds.has(p.sale_id) && !filteredSaleIds.has(p.sale_id);
    }).map(p => p.sale_id);
    if (staleSaleIds.length > 0) {
      obsoleteRemoved = await store.alerts.deleteBySaleIdsForRule(staleSaleIds, ruleId);
    }
  }

  let newAlerts = 0;
  let skippedExisting = 0;
  let priceChanges = 0;
  const changedPriceSaleIds: string[] = [];
  const matchingItems: SkinBaronItem[] = [];

  for (const item of items) {
    const existingPrice = existingMap.get(item.saleId);

    if (existingPrice !== undefined) {
      if (existingPrice === item.price) {
        skippedExisting++;
        continue;
      }
      changedPriceSaleIds.push(item.saleId);
      priceChanges++;
    }

    matchingItems.push(item);
  }

  if (changedPriceSaleIds.length > 0) {
    await store.alerts.deleteBySaleIdsForRule(changedPriceSaleIds, ruleId);
  }

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

  const unnotifiedAlerts = await store.alerts.findUnnotifiedByRuleId(ruleId);
  if (unnotifiedAlerts.length > 0) {
    const webhooks = await store.webhooks.getRuleWebhooksForNotification(ruleId);
    if (webhooks.length > 0) {
      await sendAndMarkNotifications(unnotifiedAlerts, webhooks, rule, client, deps);
    }
  }

  deps.logger.info({
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

async function sendAndMarkNotifications(
  unnotifiedAlerts: Alert[],
  webhooks: UserWebhook[],
  rule: Rule,
  client: SkinBaronClient,
  deps: ProcessRuleGroupDeps,
): Promise<void> {
  const notifiedIds: number[] = [];

  for (const alert of unnotifiedAlerts) {
    const offerUrl = client.getSkinUrl(alert.sale_id, alert.item_name);
    const item: SkinBaronItem = {
      saleId: alert.sale_id,
      itemName: alert.item_name,
      price: alert.price,
      wearValue: alert.wear_value ?? undefined,
      statTrak: alert.stattrak,
      souvenir: alert.souvenir,
      hasStickers: alert.has_stickers,
      imageUrl: alert.skin_url,
      skinUrl: offerUrl,
    };

    let anySent = false;
    for (const webhook of webhooks) {
      if (!webhook.webhook_url) continue;
      try {
        const success = await deps.notificationService.sendNotification(webhook.webhook_url, {
          item,
          skinUrl: offerUrl,
          style: webhook.notification_style || 'compact',
        });
        if (success) {
          anySent = true;
        } else {
          deps.logger.warn({
            webhookId: webhook.id,
            item: alert.item_name,
          }, '[Scheduler] Webhook notification failed to send');
        }
      } catch (error) {
        deps.logger.error({
          error: error instanceof Error ? error.message : error,
          item: alert.item_name,
        }, '[Scheduler] Webhook notification threw error');
      }
      await new Promise(resolve => setTimeout(resolve, DISCORD_DELAY_MS));
    }

    if (anySent) {
      notifiedIds.push(alert.id);
    }
  }

  if (notifiedIds.length > 0) {
    await store.alerts.markNotified(notifiedIds);
    deps.logger.info({ ruleId: rule.id, notified: notifiedIds.length, total: unnotifiedAlerts.length }, '[Scheduler] Marked alerts as notified');
  }
}
