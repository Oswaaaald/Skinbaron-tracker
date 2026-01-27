import type Database from 'better-sqlite3';
import type { Rule, CreateRule, RuleRow } from '../schemas.js';
import { CreateRuleSchema } from '../schemas.js';
import { rowToRule } from '../utils/converters.js';

export class RulesRepository {
  constructor(private db: Database.Database) {}

  create(rule: CreateRule): Rule {
    const validated = CreateRuleSchema.parse(rule);
    
    const stmt = this.db.prepare(`
      INSERT INTO rules (user_id, search_item, min_price, max_price, min_wear, max_wear, 
                        stattrak_filter, souvenir_filter, allow_stickers, webhook_ids, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      validated.allow_stickers ? 1 : 0,
      JSON.stringify(validated.webhook_ids),
      validated.enabled ? 1 : 0
    );

    return this.findById(result.lastInsertRowid as number)!;
  }

  findById(id: number): Rule | null {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE id = ?');
    const row = stmt.get(id) as RuleRow | undefined;
    return row ? rowToRule(row) : null;
  }

  findAll(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules ORDER BY created_at DESC');
    const rows = stmt.all() as RuleRow[];
    return rows.map(rowToRule);
  }

  findByUserId(userId: number): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE user_id = ? ORDER BY created_at DESC');
    const rows = stmt.all(userId) as RuleRow[];
    return rows.map(rowToRule);
  }

  findEnabled(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as RuleRow[];
    return rows.map(rowToRule);
  }

  update(id: number, updates: CreateRule): Rule | null {
    const current = this.findById(id);
    if (!current) return null;

    const validated = CreateRuleSchema.parse(updates);
    
    const stmt = this.db.prepare(`
      UPDATE rules 
      SET search_item = ?, min_price = ?, max_price = ?, min_wear = ?, max_wear = ?,
          stattrak_filter = ?, souvenir_filter = ?, allow_stickers = ?, webhook_ids = ?, 
          enabled = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run(
      validated.search_item,
      validated.min_price ?? null,
      validated.max_price ?? null,
      validated.min_wear ?? null,
      validated.max_wear ?? null,
      validated.stattrak_filter,
      validated.souvenir_filter,
      validated.allow_stickers ? 1 : 0,
      JSON.stringify(validated.webhook_ids),
      validated.enabled ? 1 : 0,
      id
    );

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

  countByUserId(userId: number): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE user_id = ?');
    const result = stmt.get(userId) as { count: number };
    return result.count;
  }

  countEnabled(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE enabled = 1');
    const result = stmt.get() as { count: number };
    return result.count;
  }
}
