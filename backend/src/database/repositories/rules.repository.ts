import { eq, and, desc, count, inArray } from 'drizzle-orm';
import { rules, ruleWebhooks } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { Rule, CreateRule } from '../schema.js';

export class RulesRepository {
  constructor(private db: AppDatabase) {}

  private async attachWebhookIds(ruleRows: Array<typeof rules.$inferSelect>): Promise<Rule[]> {
    if (ruleRows.length === 0) return [];

    const ruleIds = ruleRows.map(r => r.id);
    const webhookLinks = await this.db.select()
      .from(ruleWebhooks)
      .where(inArray(ruleWebhooks.rule_id, ruleIds));

    const webhookMap = new Map<number, number[]>();
    for (const link of webhookLinks) {
      const existing = webhookMap.get(link.rule_id) ?? [];
      existing.push(link.webhook_id);
      webhookMap.set(link.rule_id, existing);
    }

    return ruleRows.map(rule => ({
      ...rule,
      webhook_ids: webhookMap.get(rule.id) ?? [],
    }));
  }

  async findById(id: number): Promise<Rule | null> {
    const [rule] = await this.db.select().from(rules).where(eq(rules.id, id)).limit(1);
    if (!rule) return null;
    const [withWebhooks] = await this.attachWebhookIds([rule]);
    return withWebhooks ?? null;
  }

  async findByUserId(userId: number): Promise<Rule[]> {
    const ruleRows = await this.db.select()
      .from(rules)
      .where(eq(rules.user_id, userId))
      .orderBy(desc(rules.created_at));
    return this.attachWebhookIds(ruleRows);
  }

  async findAllEnabled(): Promise<Rule[]> {
    const ruleRows = await this.db.select()
      .from(rules)
      .where(eq(rules.enabled, true));
    return this.attachWebhookIds(ruleRows);
  }

  async create(ruleData: CreateRule): Promise<Rule> {
    return this.db.transaction(async (tx) => {
      const [rule] = await tx.insert(rules).values({
        user_id: ruleData.user_id,
        search_item: ruleData.search_item,
        min_price: ruleData.min_price ?? null,
        max_price: ruleData.max_price ?? null,
        min_wear: ruleData.min_wear ?? null,
        max_wear: ruleData.max_wear ?? null,
        stattrak_filter: ruleData.stattrak_filter,
        souvenir_filter: ruleData.souvenir_filter,
        sticker_filter: ruleData.sticker_filter,
        enabled: ruleData.enabled,
      }).returning();

      if (ruleData.webhook_ids.length > 0) {
        await tx.insert(ruleWebhooks).values(
          ruleData.webhook_ids.map(webhookId => ({
            rule_id: rule.id,
            webhook_id: webhookId,
          }))
        );
      }

      return { ...rule, webhook_ids: ruleData.webhook_ids };
    });
  }

  async update(id: number, updates: Partial<CreateRule>): Promise<Rule | null> {
    return this.db.transaction(async (tx) => {
      const { webhook_ids, user_id: _user_id, ...ruleUpdates } = updates;
      void _user_id;

      const [updatedRule] = await tx.update(rules)
        .set({ ...ruleUpdates, updated_at: new Date() })
        .where(eq(rules.id, id))
        .returning();

      if (!updatedRule) return null;

      // Update webhook junctions if provided
      if (webhook_ids !== undefined) {
        await tx.delete(ruleWebhooks).where(eq(ruleWebhooks.rule_id, id));
        if (webhook_ids.length > 0) {
          await tx.insert(ruleWebhooks).values(
            webhook_ids.map(wid => ({ rule_id: id, webhook_id: wid }))
          );
        }
      }

      // Fetch current webhook_ids
      const links = await tx.select({ webhook_id: ruleWebhooks.webhook_id })
        .from(ruleWebhooks)
        .where(eq(ruleWebhooks.rule_id, id));

      return { ...updatedRule, webhook_ids: links.map(l => l.webhook_id) };
    });
  }

  async delete(id: number): Promise<boolean> {
    const result = await this.db.delete(rules).where(eq(rules.id, id)).returning({ id: rules.id });
    return result.length > 0;
  }

  async enableBatch(ruleIds: number[], userId: number): Promise<number> {
    if (ruleIds.length === 0) return 0;
    const result = await this.db.update(rules)
      .set({ enabled: true, updated_at: new Date() })
      .where(and(inArray(rules.id, ruleIds), eq(rules.user_id, userId)))
      .returning({ id: rules.id });
    return result.length;
  }

  async disableBatch(ruleIds: number[], userId: number): Promise<number> {
    if (ruleIds.length === 0) return 0;
    const result = await this.db.update(rules)
      .set({ enabled: false, updated_at: new Date() })
      .where(and(inArray(rules.id, ruleIds), eq(rules.user_id, userId)))
      .returning({ id: rules.id });
    return result.length;
  }

  async deleteBatch(ruleIds: number[], userId: number): Promise<number> {
    if (ruleIds.length === 0) return 0;
    const result = await this.db.delete(rules)
      .where(and(inArray(rules.id, ruleIds), eq(rules.user_id, userId)))
      .returning({ id: rules.id });
    return result.length;
  }

  async count(userId: number): Promise<number> {
    const [result] = await this.db.select({ value: count() })
      .from(rules)
      .where(eq(rules.user_id, userId));
    return result?.value ?? 0;
  }
}
