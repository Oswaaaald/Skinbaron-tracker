import Database from 'better-sqlite3';
import { z } from 'zod';
import { appConfig } from './config.js';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

// Schema validation with Zod
export const RuleSchema = z.object({
  id: z.number().optional(),
  user_id: z.string().min(1, 'User ID is required'),
  search_item: z.string().min(1, 'Search item is required'),
  min_price: z.number().min(0).optional(),
  max_price: z.number().min(0).optional(),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  discord_webhook: z.string().url('Valid Discord webhook URL required'),
  enabled: z.boolean().default(true),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

export const AlertSchema = z.object({
  id: z.number().optional(),
  rule_id: z.number(),
  sale_id: z.string().min(1, 'Sale ID is required'),
  item_name: z.string().min(1, 'Item name is required'),
  price: z.number().min(0),
  wear_value: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().default(false),
  souvenir: z.boolean().default(false),
  skin_url: z.string().url('Valid skin URL required'),
  alert_type: z.enum(['match', 'best_deal', 'new_item']).default('match'),
  sent_at: z.string().optional(),
});

// User schema (for multi-user support)
export const UserSchema = z.object({
  id: z.number().optional(),
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

// Types inferred from schemas
export type Rule = z.infer<typeof RuleSchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type User = z.infer<typeof UserSchema>;
export type CreateRule = Omit<Rule, 'id' | 'created_at' | 'updated_at'>;
export type CreateAlert = Omit<Alert, 'id' | 'sent_at'>;
export type CreateUser = Omit<User, 'id' | 'created_at' | 'updated_at'>;

export class Store {
  private db: Database.Database;

  constructor() {
    // Create directory if it doesn't exist
    const dbPath = appConfig.SQLITE_PATH;
    const dbDir = dirname(dbPath);
    
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }

    // Initialize database
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    
    this.initializeTables();
    this.initializeUserTables(); // Add multi-user support
    console.log(`✅ SQLite database initialized at: ${dbPath}`);
  }

  private initializeTables() {
    // Create rules table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        search_item TEXT NOT NULL,
        min_price REAL,
        max_price REAL,
        min_wear REAL,
        max_wear REAL,
        stattrak BOOLEAN DEFAULT 0,
        souvenir BOOLEAN DEFAULT 0,
        discord_webhook TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create alerts table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id INTEGER,
        sale_id TEXT UNIQUE NOT NULL,
        item_name TEXT NOT NULL,
        price REAL NOT NULL,
        wear_value REAL,
        stattrak BOOLEAN DEFAULT 0,
        souvenir BOOLEAN DEFAULT 0,
        skin_url TEXT NOT NULL,
        alert_type TEXT DEFAULT 'match',
        sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE
      )
    `);

    // Create indexes for better performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_rules_user_id ON rules (user_id);
      CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
      CREATE INDEX IF NOT EXISTS idx_alerts_sale_id ON alerts (sale_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_sent_at ON alerts (sent_at);
    `);

    console.log('✅ Database tables initialized');
  }

  private initializeUserTables() {
    // Create users table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 20),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create user webhooks table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 50),
        webhook_url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, name)
      )
    `);

    // Add indexes for users
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
      CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON user_webhooks(user_id);
    `);

    console.log('✅ User tables initialized');
  }

  // Rules CRUD operations
  createRule(rule: CreateRule): Rule {
    const validated = RuleSchema.omit({ id: true, created_at: true, updated_at: true }).parse(rule);
    
    const stmt = this.db.prepare(`
      INSERT INTO rules (user_id, search_item, min_price, max_price, min_wear, max_wear, 
                        stattrak, souvenir, discord_webhook, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      validated.user_id,
      validated.search_item,
      validated.min_price ?? null,
      validated.max_price ?? null,
      validated.min_wear ?? null,
      validated.max_wear ?? null,
      validated.stattrak ? 1 : 0,
      validated.souvenir ? 1 : 0,
      validated.discord_webhook,
      validated.enabled ? 1 : 0
    );

    return this.getRuleById(result.lastInsertRowid as number)!;
  }

  getRuleById(id: number): Rule | null {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE id = ?');
    const row = stmt.get(id) as any;
    
    if (!row) return null;

    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
      enabled: Boolean(row.enabled),
    };
  }

  getAllRules(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules ORDER BY created_at DESC');
    const rows = stmt.all() as any[];
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
      enabled: Boolean(row.enabled),
    }));
  }

  getEnabledRules(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as any[];
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
      enabled: Boolean(row.enabled),
    }));
  }

  updateRule(id: number, updates: Partial<CreateRule>): Rule | null {
    const current = this.getRuleById(id);
    if (!current) return null;

    const validated = RuleSchema.omit({ id: true, created_at: true, updated_at: true }).partial().parse(updates);
    
    const fields = Object.keys(validated).filter(key => validated[key as keyof typeof validated] !== undefined);
    if (fields.length === 0) return current;

    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => {
      const value = validated[field as keyof typeof validated];
      if (typeof value === 'boolean') return value ? 1 : 0;
      return value;
    });

    const stmt = this.db.prepare(`
      UPDATE rules 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `);

    stmt.run(...values, id);
    return this.getRuleById(id);
  }

  deleteRule(id: number): boolean {
    const stmt = this.db.prepare('DELETE FROM rules WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // Alerts CRUD operations
  createAlert(alert: CreateAlert): Alert {
    const validated = AlertSchema.omit({ id: true, sent_at: true }).parse(alert);
    
    const stmt = this.db.prepare(`
      INSERT INTO alerts (rule_id, sale_id, item_name, price, wear_value, 
                         stattrak, souvenir, skin_url, alert_type)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
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

      return this.getAlertById(result.lastInsertRowid as number)!;
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        // Sale already processed
        throw new Error('DUPLICATE_SALE');
      }
      throw error;
    }
  }

  getAlertById(id: number): Alert | null {
    const stmt = this.db.prepare('SELECT * FROM alerts WHERE id = ?');
    const row = stmt.get(id) as any;
    
    if (!row) return null;

    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    };
  }

  getAlerts(limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT * FROM alerts 
      ORDER BY sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(limit, offset) as any[];
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    }));
  }

  getAlertsBySaleId(saleId: string): Alert | null {
    const stmt = this.db.prepare('SELECT * FROM alerts WHERE sale_id = ? LIMIT 1');
    const row = stmt.get(saleId) as any;
    
    if (!row) return null;

    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    };
  }

  // Utility methods
  isProcessed(saleId: string): boolean {
    const stmt = this.db.prepare('SELECT 1 FROM alerts WHERE sale_id = ? LIMIT 1');
    return stmt.get(saleId) !== undefined;
  }

  getStats() {
    const totalRules = this.db.prepare('SELECT COUNT(*) as count FROM rules').get() as { count: number };
    const enabledRules = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE enabled = 1').get() as { count: number };
    const totalAlerts = this.db.prepare('SELECT COUNT(*) as count FROM alerts').get() as { count: number };
    const todayAlerts = this.db.prepare(`
      SELECT COUNT(*) as count FROM alerts 
      WHERE DATE(sent_at) = DATE('now')
    `).get() as { count: number };

    return {
      totalRules: totalRules.count,
      enabledRules: enabledRules.count,
      totalAlerts: totalAlerts.count,
      todayAlerts: todayAlerts.count,
    };
  }

  // Cleanup old alerts (keep last 30 days)
  cleanupOldAlerts(): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-30 days')
    `);
    const result = stmt.run();
    return result.changes;
  }

  // User management methods
  createUser(user: CreateUser): User {
    const validated = UserSchema.omit({ id: true, created_at: true, updated_at: true }).parse(user);
    
    const stmt = this.db.prepare(`
      INSERT INTO users (username, email, password_hash)
      VALUES (?, ?, ?)
    `);

    try {
      const result = stmt.run(validated.username, validated.email, validated.password_hash);
      return this.getUserById(result.lastInsertRowid as number)!;
    } catch (error: any) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        if (error.message.includes('users.email')) {
          throw new Error('Email already exists');
        }
        if (error.message.includes('users.username')) {
          throw new Error('Username already taken');
        }
      }
      throw error;
    }
  }

  getUserById(id: number): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE id = ?');
    const row = stmt.get(id) as any;
    return row ? UserSchema.parse(row) : null;
  }

  getUserByEmail(email: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE email = ?');
    const row = stmt.get(email) as any;
    return row ? UserSchema.parse(row) : null;
  }

  getUserByUsername(username: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE username = ?');
    const row = stmt.get(username) as any;
    return row ? UserSchema.parse(row) : null;
  }

  updateUser(id: number, updates: Partial<CreateUser>): User {
    const currentUser = this.getUserById(id);
    if (!currentUser) {
      throw new Error('User not found');
    }

    const validatedUpdates = UserSchema.omit({ id: true, created_at: true }).partial().parse(updates);
    
    const fields = Object.keys(validatedUpdates).filter(key => key !== 'updated_at');
    if (fields.length === 0) {
      return currentUser;
    }

    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => (validatedUpdates as any)[field]);
    
    const stmt = this.db.prepare(`
      UPDATE users 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run(...values, id);
    return this.getUserById(id)!;
  }

  deleteUser(id: number): boolean {
    const stmt = this.db.prepare('DELETE FROM users WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  close() {
    this.db.close();
  }
}

// Singleton instance
let storeInstance: Store | null = null;

export const getStore = (): Store => {
  if (!storeInstance) {
    storeInstance = new Store();
  }
  return storeInstance;
};

export default getStore;