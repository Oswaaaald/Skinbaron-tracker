import type Database from 'better-sqlite3';
import type { Rule, CreateRule, RuleRow } from '../schemas.js';
import { CreateRuleSchema } from '../schemas.js';
import { rowToRule } from '../utils/converters.js';

export class RulesRepository {
  constructor(private db: Database.Database) {}

  /**
   * Load webhook_ids from the junction table for a single rule
   */
  private loadWebhookIds(ruleId: number): number[] {
    const stmt = this.db.prepare('SELECT webhook_id FROM rule_webhooks WHERE rule_id = ?');
    const rows = stmt.all(ruleId) as Array<{ webhook_id: number }>;
    return rows.map(r => r.webhook_id);
  }

  /**
   * Load webhook_ids from the junction table for multiple rules in one query
   */
  private loadWebhookIdsBatch(ruleIds: number[]): Map<number, number[]> {
    const map = new Map<number, number[]>();
    if (ruleIds.length === 0) return map;
    
    const placeholders = ruleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`SELECT rule_id, webhook_id FROM rule_webhooks WHERE rule_id IN (${placeholders})`);
    const rows = stmt.all(...ruleIds) as Array<{ rule_id: number; webhook_id: number }>;
    
    for (const row of rows) {
      const existing = map.get(row.rule_id) ?? [];
      existing.push(row.webhook_id);
      map.set(row.rule_id, existing);
    }
    
    return map;
  }

  /**
   * Set webhook_ids for a rule (replace all associations)
   */
  private setWebhookIds(ruleId: number, webhookIds: number[]): void {
    this.db.prepare('DELETE FROM rule_webhooks WHERE rule_id = ?').run(ruleId);
    
    if (webhookIds.length > 0) {
      const insertStmt = this.db.prepare('INSERT OR IGNORE INTO rule_webhooks (rule_id, webhook_id) VALUES (?, ?)');
      for (const webhookId of webhookIds) {
        insertStmt.run(ruleId, webhookId);
      }
    }
  }

  /**
   * Convert a rule row + webhook_ids into a full Rule object
   */
  private toRuleWithWebhooks(row: RuleRow, webhookIds: number[]): Rule {
    const rule = rowToRule(row);
    rule.webhook_ids = webhookIds;
    return rule;
  }

  create(rule: CreateRule): Rule {
    const validated = CreateRuleSchema.parse(rule);
    
    // Wrap in transaction to ensure atomicity (rule + webhook associations)
    const createTransaction = this.db.transaction(() => {
      const stmt = this.db.prepare(`
        INSERT INTO rules (user_id, search_item, min_price, max_price, min_wear, max_wear, 
                          stattrak_filter, souvenir_filter, sticker_filter, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        validated.user_id,
        validated.search_item,
        validated.min_price ?? null,
        validated.max_price ?? null,
        validated.min_wear ?? null,
        validated.max_wear ?? null,
        validated.stattrak_filter,
        validated.souvenir_filter,
        validated.sticker_filter,
        validated.enabled ? 1 : 0
      );

      const ruleId = result.lastInsertRowid as number;
      
      // Insert webhook associations into junction table
      if (validated.webhook_ids && validated.webhook_ids.length > 0) {
        this.setWebhookIds(ruleId, validated.webhook_ids);
      }

      return ruleId;
    });

    const ruleId = createTransaction();
    const created = this.findById(ruleId);
    if (!created) throw new Error('Failed to create rule');
    return created;
  }

  findById(id: number): Rule | null {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE id = ?');
    const row = stmt.get(id) as RuleRow | undefined;
    if (!row) return null;
    return this.toRuleWithWebhooks(row, this.loadWebhookIds(id));
  }

  findByUserId(userId: number): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE user_id = ? ORDER BY created_at DESC');
    const rows = stmt.all(userId) as RuleRow[];
    const webhookMap = this.loadWebhookIdsBatch(rows.map(r => r.id));
    return rows.map(row => this.toRuleWithWebhooks(row, webhookMap.get(row.id) ?? []));
  }

  findEnabled(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as RuleRow[];
    const webhookMap = this.loadWebhookIdsBatch(rows.map(r => r.id));
    return rows.map(row => this.toRuleWithWebhooks(row, webhookMap.get(row.id) ?? []));
  }

  update(id: number, updates: Partial<CreateRule>): Rule | null {
    const current = this.findById(id);
    if (!current) return null;

    const validated = CreateRuleSchema.partial().parse(updates);
    
    const fields: string[] = [];
    const values: (string | number)[] = [];

    if (validated.search_item !== undefined) {
      fields.push('search_item = ?');
      values.push(validated.search_item);
    }

    if (validated.min_price !== undefined) {
      fields.push('min_price = ?');
      values.push(validated.min_price ?? null);
    }

    if (validated.max_price !== undefined) {
      fields.push('max_price = ?');
      values.push(validated.max_price ?? null);
    }

    if (validated.min_wear !== undefined) {
      fields.push('min_wear = ?');
      values.push(validated.min_wear ?? null);
    }

    if (validated.max_wear !== undefined) {
      fields.push('max_wear = ?');
      values.push(validated.max_wear ?? null);
    }

    if (validated.stattrak_filter !== undefined) {
      fields.push('stattrak_filter = ?');
      values.push(validated.stattrak_filter);
    }

    if (validated.souvenir_filter !== undefined) {
      fields.push('souvenir_filter = ?');
      values.push(validated.souvenir_filter);
    }

    if (validated.sticker_filter !== undefined) {
      fields.push('sticker_filter = ?');
      values.push(validated.sticker_filter);
    }

    if (validated.enabled !== undefined) {
      fields.push('enabled = ?');
      values.push(validated.enabled ? 1 : 0);
    }

    if (fields.length > 0) {
      fields.push('updated_at = CURRENT_TIMESTAMP');
      const setClause = fields.join(', ');
      const stmt = this.db.prepare(`UPDATE rules SET ${setClause} WHERE id = ?`);
      stmt.run(...values, id);
    }

    // Update webhook associations in junction table
    if (validated.webhook_ids !== undefined) {
      this.setWebhookIds(id, validated.webhook_ids);
    }

    return this.findById(id);
  }

  delete(id: number): boolean {
    const stmt = this.db.prepare('DELETE FROM rules WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // Batch operations
  enableBatch(ruleIds: number[], userId: number): number {
    if (ruleIds.length === 0) return 0;
    const placeholders = ruleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`UPDATE rules SET enabled = 1 WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...ruleIds, userId);
    return result.changes;
  }

  disableBatch(ruleIds: number[], userId: number): number {
    if (ruleIds.length === 0) return 0;
    const placeholders = ruleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`UPDATE rules SET enabled = 0 WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...ruleIds, userId);
    return result.changes;
  }

  deleteBatch(ruleIds: number[], userId: number): number {
    if (ruleIds.length === 0) return 0;
    const placeholders = ruleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`DELETE FROM rules WHERE id IN (${placeholders}) AND user_id = ?`);
    const result = stmt.run(...ruleIds, userId);
    return result.changes;
  }

  count(userId: number): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE user_id = ?');
    const result = stmt.get(userId) as { count: number };
    return result.count;
  }
}
