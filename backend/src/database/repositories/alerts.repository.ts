import type Database from 'better-sqlite3';
import type { Alert, CreateAlert, AlertRow } from '../schemas.js';
import { AlertSchema } from '../schemas.js';
import { rowToAlert } from '../utils/converters.js';

/** Alert type counts by category */
export interface AlertTypeCounts {
  match: number;
  best_deal: number;
  new_item: number;
}

export class AlertsRepository {
  constructor(private db: Database.Database) {}

  create(alert: CreateAlert): Alert {
    try {
      const validated = AlertSchema.omit({ id: true, sent_at: true }).parse(alert);
      
      const stmt = this.db.prepare(`
        INSERT INTO alerts (rule_id, sale_id, item_name, price, wear_value, 
                           stattrak, souvenir, skin_url, alert_type)
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
        validated.skin_url,
        validated.alert_type
      );

      const created = this.findById(result.lastInsertRowid as number);
      if (!created) throw new Error('Failed to create alert');
      return created;
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

    const placeholders = validated.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ');
    
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO alerts (rule_id, sale_id, item_name, price, wear_value, 
                                     stattrak, souvenir, skin_url, alert_type)
      VALUES ${placeholders}
    `);

    const values = validated.flatMap(alert => [
      alert.rule_id,
      alert.sale_id,
      alert.item_name,
      alert.price,
      alert.wear_value ?? null,
      alert.stattrak ? 1 : 0,
      alert.souvenir ? 1 : 0,
      alert.skin_url,
      alert.alert_type
    ]);

    const insertMany = this.db.transaction(() => {
      return stmt.run(...values);
    });

    const result = insertMany();
    return result.changes;
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
  findBySaleIds(saleIds: string[]): Alert[] {
    if (saleIds.length === 0) return [];
    const placeholders = saleIds.map(() => '?').join(',');
    const stmt = this.db.prepare(`SELECT * FROM alerts WHERE sale_id IN (${placeholders})`);
    const rows = stmt.all(...saleIds) as AlertRow[];
    return rows.map(rowToAlert);
  }
  findByUserId(userId: number, limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(userId, limit, offset) as AlertRow[];
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
   * Get alert counts by type for a user - efficient SQL aggregation
   * Replaces fetching all alerts and filtering in memory
   */
  countByAlertType(userId: number): AlertTypeCounts {
    const stmt = this.db.prepare(`
      SELECT 
        alert_type,
        COUNT(*) as count
      FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ?
      GROUP BY alert_type
    `);
    const rows = stmt.all(userId) as Array<{ alert_type: string; count: number }>;
    
    // Initialize with zeros and populate from results
    const counts: AlertTypeCounts = { match: 0, best_deal: 0, new_item: 0 };
    for (const row of rows) {
      if (row.alert_type in counts) {
        counts[row.alert_type as keyof AlertTypeCounts] = row.count;
      }
    }
    return counts;
  }
}
