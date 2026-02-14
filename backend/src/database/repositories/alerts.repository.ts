import { eq, and, desc, asc, count, sql, ilike, inArray, isNull, getTableColumns } from 'drizzle-orm';
import type { SQL } from 'drizzle-orm';
import { alerts, rules } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { Alert, CreateAlert } from '../schema.js';

export class AlertsRepository {
  constructor(private db: AppDatabase) {}

  async findByUserId(
    userId: number,
    limit: number = 0,
    offset: number = 0,
    options?: {
      ruleId?: number;
      itemName?: string;
      sortBy?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
    }
  ): Promise<Alert[]> {
    const conditions: SQL[] = [eq(rules.user_id, userId)];

    if (options?.ruleId !== undefined) {
      conditions.push(eq(alerts.rule_id, options.ruleId));
    }
    if (options?.itemName) {
      const escaped = options.itemName.replace(/[%_\\]/g, '\\$&');
      conditions.push(ilike(alerts.item_name, `%${escaped}%`));
    }

    let orderByClause: SQL;
    switch (options?.sortBy) {
      case 'price_asc': orderByClause = asc(alerts.price); break;
      case 'price_desc': orderByClause = desc(alerts.price); break;
      case 'wear_asc': orderByClause = sql`${alerts.wear_value} ASC NULLS LAST`; break;
      case 'wear_desc': orderByClause = sql`${alerts.wear_value} DESC NULLS LAST`; break;
      default: orderByClause = desc(alerts.sent_at); break;
    }

    const alertCols = getTableColumns(alerts);

    if (limit > 0) {
      return this.db.select(alertCols)
        .from(alerts)
        .innerJoin(rules, eq(alerts.rule_id, rules.id))
        .where(and(...conditions))
        .orderBy(orderByClause)
        .limit(limit)
        .offset(offset);
    }

    return this.db.select(alertCols)
      .from(alerts)
      .innerJoin(rules, eq(alerts.rule_id, rules.id))
      .where(and(...conditions))
      .orderBy(orderByClause);
  }

  async createBatch(alertsData: CreateAlert[]): Promise<number> {
    if (alertsData.length === 0) return 0;
    const result = await this.db.insert(alerts)
      .values(alertsData)
      .onConflictDoNothing({ target: [alerts.rule_id, alerts.sale_id] })
      .returning({ id: alerts.id });
    return result.length;
  }

  async findSaleIdPricesByRuleId(ruleId: number): Promise<Array<{ sale_id: string; price: number }>> {
    return this.db.select({
      sale_id: alerts.sale_id,
      price: alerts.price,
    }).from(alerts)
      .where(eq(alerts.rule_id, ruleId));
  }

  async deleteBySaleIdsForRule(saleIds: string[], ruleId: number): Promise<number> {
    if (saleIds.length === 0) return 0;
    const result = await this.db.delete(alerts)
      .where(and(
        inArray(alerts.sale_id, saleIds),
        eq(alerts.rule_id, ruleId)
      ))
      .returning({ id: alerts.id });
    return result.length;
  }

  async deleteBySaleIdAndRuleId(saleId: string, ruleId: number): Promise<void> {
    await this.db.delete(alerts)
      .where(and(eq(alerts.sale_id, saleId), eq(alerts.rule_id, ruleId)));
  }

  async deleteAllByUserId(userId: number): Promise<number> {
    const result = await this.db.delete(alerts)
      .where(
        inArray(
          alerts.rule_id,
          this.db.select({ id: rules.id }).from(rules).where(eq(rules.user_id, userId))
        )
      )
      .returning({ id: alerts.id });
    return result.length;
  }

  async countByUserId(userId: number): Promise<number> {
    const [result] = await this.db.select({ value: count() })
      .from(alerts)
      .innerJoin(rules, eq(alerts.rule_id, rules.id))
      .where(eq(rules.user_id, userId));
    return result?.value ?? 0;
  }

  async getUniqueItemNames(userId: number): Promise<string[]> {
    const result = await this.db.selectDistinct({ item_name: alerts.item_name })
      .from(alerts)
      .innerJoin(rules, eq(alerts.rule_id, rules.id))
      .where(eq(rules.user_id, userId))
      .orderBy(alerts.item_name);
    return result.map(r => r.item_name);
  }

  /**
   * Find alerts for a rule that have not yet been notified (notified_at IS NULL).
   */
  async findUnnotifiedByRuleId(ruleId: number): Promise<Alert[]> {
    const alertCols = getTableColumns(alerts);
    return this.db.select(alertCols)
      .from(alerts)
      .where(and(eq(alerts.rule_id, ruleId), isNull(alerts.notified_at)));
  }

  /**
   * Mark alerts as notified by setting notified_at to now.
   */
  async markNotified(alertIds: number[]): Promise<void> {
    if (alertIds.length === 0) return;
    await this.db.update(alerts)
      .set({ notified_at: new Date() })
      .where(inArray(alerts.id, alertIds));
  }
}
