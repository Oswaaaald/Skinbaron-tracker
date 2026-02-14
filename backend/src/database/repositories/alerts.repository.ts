import type Database from 'better-sqlite3';
import type { Alert, CreateAlert, AlertRow } from '../schemas.js';
import { AlertSchema } from '../schemas.js';
import { rowToAlert } from '../utils/converters.js';

export class AlertsRepository {
  constructor(private db: Database.Database) {}

  /**
   * Get unique item names for a user's alerts (for filtering UI)
   */
  getUniqueItemNames(userId: number): string[] {
    const stmt = this.db.prepare(`
      SELECT DISTINCT a.item_name 
      FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ?
      ORDER BY a.item_name ASC
    `);
    const rows = stmt.all(userId) as Array<{ item_name: string }>;
    return rows.map(row => row.item_name);
  }

  create(alert: CreateAlert): Alert {
    try {
      const validated = AlertSchema.omit({ id: true, sent_at: true }).parse(alert);
      
      const stmt = this.db.prepare(`
        INSERT INTO alerts (rule_id, sale_id, item_name, price, wear_value, 
                           stattrak, souvenir, has_stickers, skin_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        validated.rule_id,
        validated.sale_id,
        validated.item_name,
        validated.price,
        validated.wear_value ?? null,
        validated.stattrak ? 1 : 0,
        validated.souvenir ? 1 : 0,
        validated.has_stickers ? 1 : 0,
        validated.skin_url
      );

      return this.findById(result.lastInsertRowid as number)!;
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw new Error('DUPLICATE_SALE');
      }
      throw error;
    }
  }

  createBatch(alerts: CreateAlert[]): number {
    if (alerts.length === 0) return 0;

    const validated = alerts.map(alert => 
      AlertSchema.omit({ id: true, sent_at: true }).parse(alert)
    );

    // Chunk inserts to stay within SQLite variable limits (max ~999 variables per statement)
    const VARS_PER_ROW = 9;
    const MAX_ROWS_PER_CHUNK = Math.floor(900 / VARS_PER_ROW); // ~100 rows per chunk
    
    const insertChunked = this.db.transaction(() => {
      let totalChanges = 0;
      for (let i = 0; i < validated.length; i += MAX_ROWS_PER_CHUNK) {
        const chunk = validated.slice(i, i + MAX_ROWS_PER_CHUNK);
        const placeholders = chunk.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');

        const stmt = this.db.prepare(`
          INSERT OR IGNORE INTO alerts (rule_id, sale_id, item_name, price, wear_value, 
                                         stattrak, souvenir, has_stickers, skin_url)
          VALUES ${placeholders}
        `);

        const values = chunk.flatMap(alert => [
          alert.rule_id,
          alert.sale_id,
          alert.item_name,
          alert.price,
          alert.wear_value ?? null,
          alert.stattrak ? 1 : 0,
          alert.souvenir ? 1 : 0,
          alert.has_stickers ? 1 : 0,
          alert.skin_url
        ]);

        const result = stmt.run(...values);
        totalChanges += result.changes;
      }
      return totalChanges;
    });

    return insertChunked();
  }

  findById(id: number): Alert | null {
    const stmt = this.db.prepare('SELECT * FROM alerts WHERE id = ?');
    const row = stmt.get(id) as AlertRow | undefined;
    return row ? rowToAlert(row) : null;
  }

  findAll(limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT * FROM alerts 
      ORDER BY sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(limit, offset) as AlertRow[];
    return rows.map(rowToAlert);
  }

  findBySaleId(saleId: string): Alert | null {
    const stmt = this.db.prepare('SELECT * FROM alerts WHERE sale_id = ? LIMIT 1');
    const row = stmt.get(saleId) as AlertRow | undefined;
    return row ? rowToAlert(row) : null;
  }
  findBySaleIds(saleIds: string[], ruleId?: number): Alert[] {
    if (saleIds.length === 0) return [];
    const placeholders = saleIds.map(() => '?').join(',');
    // Scope to a specific rule to avoid cross-rule dedup
    if (ruleId !== undefined) {
      const stmt = this.db.prepare(`SELECT * FROM alerts WHERE sale_id IN (${placeholders}) AND rule_id = ?`);
      const rows = stmt.all(...saleIds, ruleId) as AlertRow[];
      return rows.map(rowToAlert);
    }
    const stmt = this.db.prepare(`SELECT * FROM alerts WHERE sale_id IN (${placeholders})`);
    const rows = stmt.all(...saleIds) as AlertRow[];
    return rows.map(rowToAlert);
  }
  findByUserId(
    userId: number, 
    limit: number = 50, 
    offset: number = 0,
    options?: {
      ruleId?: number;
      itemName?: string;
      sortBy?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
    }
  ): Alert[] {
    let query = `
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ?
    `;
    const params: (string | number)[] = [userId];

    // Add rule_id filter (SQL instead of JS filtering)
    if (options?.ruleId !== undefined) {
      query += ` AND a.rule_id = ?`;
      params.push(options.ruleId);
    }

    // Add item name filter
    if (options?.itemName) {
      query += ` AND a.item_name LIKE ? ESCAPE '\\'`;
      const escaped = options.itemName.replace(/[%_\\]/g, '\\$&');
      params.push(`%${escaped}%`);
    }

    // Add sorting
    switch (options?.sortBy) {
      case 'price_asc':
        query += ` ORDER BY a.price ASC`;
        break;
      case 'price_desc':
        query += ` ORDER BY a.price DESC`;
        break;
      case 'wear_asc':
        query += ` ORDER BY a.wear_value ASC NULLS LAST`;
        break;
      case 'wear_desc':
        query += ` ORDER BY a.wear_value DESC NULLS LAST`;
        break;
      case 'date':
      default:
        query += ` ORDER BY a.sent_at DESC`;
        break;
    }

    // Apply pagination only when limit > 0 (0 = no limit)
    if (limit > 0) {
      query += ` LIMIT ? OFFSET ?`;
      params.push(limit, offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as AlertRow[];
    return rows.map(rowToAlert);
  }

  findByIdForUser(alertId: number, userId: number): Alert | null {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.id = ? AND r.user_id = ?
    `);
    const row = stmt.get(alertId, userId) as AlertRow | undefined;
    return row ? rowToAlert(row) : null;
  }

  findByRuleIdForUser(ruleId: number, userId: number, limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.rule_id = ? AND r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(ruleId, userId, limit, offset) as AlertRow[];
    return rows.map(rowToAlert);
  }

  deleteByRuleId(ruleId: number): boolean {
    const stmt = this.db.prepare('DELETE FROM alerts WHERE rule_id = ?');
    const result = stmt.run(ruleId);
    return result.changes > 0;
  }

  deleteByUserId(userId: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `);
    const result = stmt.run(userId);
    return result.changes;
  }

  countByUserId(userId: number): number {
    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ?
    `);
    const result = stmt.get(userId) as { count: number };
    return result.count;
  }

  /**
   * Get all alerts for a specific rule
   */
  findByRuleId(ruleId: number): Alert[] {
    const stmt = this.db.prepare(`
      SELECT * FROM alerts 
      WHERE rule_id = ? 
      ORDER BY sent_at DESC
    `);
    const rows = stmt.all(ruleId) as AlertRow[];
    return rows.map(rowToAlert);
  }

  /**
   * Delete alerts by sale_ids that are no longer available
   */
  deleteBySaleIds(saleIds: string[]): number {
    if (saleIds.length === 0) return 0;
    const placeholders = saleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`DELETE FROM alerts WHERE sale_id IN (${placeholders})`);
    const result = stmt.run(...saleIds);
    return result.changes;
  }

  /**
   * Delete a specific alert by sale_id and rule_id
   */
  deleteBySaleIdAndRuleId(saleId: string, ruleId: number): boolean {
    const stmt = this.db.prepare('DELETE FROM alerts WHERE sale_id = ? AND rule_id = ?');
    const result = stmt.run(saleId, ruleId);
    return result.changes > 0;
  }

  /**
   * Lightweight: returns only sale_id + price for the scheduler
   * Avoids loading full Alert objects with all columns
   */
  findSaleIdPricesByRuleId(ruleId: number): Array<{ sale_id: string; price: number }> {
    const stmt = this.db.prepare('SELECT sale_id, price FROM alerts WHERE rule_id = ?');
    return stmt.all(ruleId) as Array<{ sale_id: string; price: number }>;
  }

  /**
   * Batch delete alerts by sale_ids scoped to a specific rule (avoids cross-rule deletion)
   */
  deleteBySaleIdsForRule(saleIds: string[], ruleId: number): number {
    if (saleIds.length === 0) return 0;
    const placeholders = saleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`DELETE FROM alerts WHERE sale_id IN (${placeholders}) AND rule_id = ?`);
    const result = stmt.run(...saleIds, ruleId);
    return result.changes;
  }
}
