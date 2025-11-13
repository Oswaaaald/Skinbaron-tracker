import Database from 'better-sqlite3';
import { z } from 'zod';
import { appConfig } from './config.js';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import CryptoJS from 'crypto-js';

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
  webhook_ids: z.array(z.number()).min(1, 'At least one webhook ID is required'),
  enabled: z.boolean().default(true),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

export const CreateRuleSchema = RuleSchema.omit({ id: true, created_at: true, updated_at: true });

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

// User schemas (for multi-user support)
export const CreateUserSchema = z.object({
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
});

export const UserSchema = z.object({
  id: z.number(),
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});

// User webhook schemas (encrypted storage)
export const CreateUserWebhookSchema = z.object({
  name: z.string().min(1).max(50),
  webhook_url: z.string().url('Valid webhook URL required'),
  webhook_type: z.enum(['discord', 'slack', 'teams', 'generic']).default('discord'),
  is_active: z.boolean().default(true),
});

export const UserWebhookSchema = z.object({
  id: z.number(),
  user_id: z.number(),
  name: z.string().min(1).max(50),
  webhook_url_encrypted: z.string(), // Encrypted storage
  webhook_type: z.enum(['discord', 'slack', 'teams', 'generic']),
  is_active: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

// Types inferred from schemas
export type Rule = z.infer<typeof RuleSchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type User = z.infer<typeof UserSchema>;
export type CreateUser = z.infer<typeof CreateUserSchema>;
export type CreateRule = Omit<Rule, 'id' | 'created_at' | 'updated_at'>;
export type CreateAlert = Omit<Alert, 'id' | 'sent_at'>;

export type UserWebhook = z.infer<typeof UserWebhookSchema> & {
  webhook_url?: string; // Decrypted URL (not stored)
};
export type CreateUserWebhook = z.infer<typeof CreateUserWebhookSchema>;

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
        min_wear REAL CHECK (min_wear >= 0 AND min_wear <= 1),
        max_wear REAL CHECK (max_wear >= 0 AND max_wear <= 1),
        stattrak BOOLEAN DEFAULT 0,
        souvenir BOOLEAN DEFAULT 0,
        webhook_ids TEXT, -- JSON array of webhook IDs
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
        sale_id TEXT NOT NULL,
        item_name TEXT NOT NULL,
        price REAL NOT NULL,
        wear_value REAL,
        stattrak BOOLEAN DEFAULT 0,
        souvenir BOOLEAN DEFAULT 0,
        skin_url TEXT NOT NULL,
        alert_type TEXT DEFAULT 'match',
        sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
        UNIQUE(rule_id, sale_id)
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
        webhook_url_encrypted TEXT NOT NULL,
        webhook_type TEXT DEFAULT 'discord' CHECK(webhook_type IN ('discord', 'slack', 'teams', 'generic')),
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
    const validated = CreateRuleSchema.parse(rule);
    
    const stmt = this.db.prepare(`
      INSERT INTO rules (user_id, search_item, min_price, max_price, min_wear, max_wear, 
                        stattrak, souvenir, webhook_ids, enabled)
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
      JSON.stringify(validated.webhook_ids),
      validated.enabled ? 1 : 0
    );

    return this.getRuleById(result.lastInsertRowid as number)!;
  }

  getRuleById(id: number): Rule | null {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE id = ?');
    const row = stmt.get(id) as any;
    
    if (!row) return null;
    
    let webhookIds: number[] = [];
    if (row.webhook_ids) {
      try {
        const parsed = JSON.parse(row.webhook_ids);
        if (Array.isArray(parsed)) {
          webhookIds = parsed.filter(id => typeof id === 'number' && !isNaN(id));
        }
      } catch (error) {
        console.warn(`Failed to parse webhook_ids for rule ${row.id}:`, row.webhook_ids);
      }
    }
    
    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
      enabled: Boolean(row.enabled),
      webhook_ids: webhookIds,
    };
  }  getAllRules(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules ORDER BY created_at DESC');
    const rows = stmt.all() as any[];
    
    return rows.map(row => {
      let webhookIds: number[] = [];
      if (row.webhook_ids) {
        try {
          const parsed = JSON.parse(row.webhook_ids);
          if (Array.isArray(parsed)) {
            webhookIds = parsed.filter(id => typeof id === 'number' && !isNaN(id));
          }
        } catch (error) {
          console.warn(`Failed to parse webhook_ids for rule ${row.id}:`, row.webhook_ids);
        }
      }
      
      return {
        ...row,
        stattrak: Boolean(row.stattrak),
        souvenir: Boolean(row.souvenir),
        enabled: Boolean(row.enabled),
        webhook_ids: webhookIds,
      };
    });
  }

  // Get rules for a specific user (for multi-user support)
  getRulesByUserId(userId: number): Rule[] {
    // Handle both old format (TEXT user_id) and new format (INTEGER user_id)
    const stmt = this.db.prepare('SELECT * FROM rules WHERE user_id = ? ORDER BY created_at DESC');
    const rows = stmt.all(userId.toString()) as any[];
    
    return rows.map(row => {
      let webhookIds: number[] = [];
      
      if (row.webhook_ids) {
        try {
          const parsed = JSON.parse(row.webhook_ids);
          // Ensure it's an array of numbers
          if (Array.isArray(parsed)) {
            webhookIds = parsed.filter(id => typeof id === 'number' && !isNaN(id));
          }
        } catch (error) {
          console.warn(`Failed to parse webhook_ids for rule ${row.id}:`, row.webhook_ids);
        }
      }
      
      return {
        ...row,
        user_id: row.user_id, // Keep original format for now
        stattrak: Boolean(row.stattrak),
        souvenir: Boolean(row.souvenir),
        enabled: Boolean(row.enabled),
        webhook_ids: webhookIds,
      };
    });
  }

  getEnabledRules(): Rule[] {
    const stmt = this.db.prepare('SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as any[];
    
    return rows.map(row => {
      let webhookIds: number[] = [];
      if (row.webhook_ids) {
        try {
          const parsed = JSON.parse(row.webhook_ids);
          if (Array.isArray(parsed)) {
            webhookIds = parsed.filter(id => typeof id === 'number' && !isNaN(id));
          }
        } catch (error) {
          console.warn(`Failed to parse webhook_ids for rule ${row.id}:`, row.webhook_ids);
        }
      }
      
      return {
        ...row,
        stattrak: Boolean(row.stattrak),
        souvenir: Boolean(row.souvenir),
        enabled: Boolean(row.enabled),
        webhook_ids: webhookIds,
      };
    });
  }

  updateRule(id: number, updates: CreateRule): Rule | null {
    const current = this.getRuleById(id);
    if (!current) return null;

    const validated = CreateRuleSchema.parse(updates);
    
    const stmt = this.db.prepare(`
      UPDATE rules 
      SET user_id = ?, search_item = ?, min_price = ?, max_price = ?, min_wear = ?, max_wear = ?, 
          stattrak = ?, souvenir = ?, webhook_ids = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run(
      validated.user_id,
      validated.search_item,
      validated.min_price ?? null,
      validated.max_price ?? null,
      validated.min_wear ?? null,
      validated.max_wear ?? null,
      validated.stattrak ? 1 : 0,
      validated.souvenir ? 1 : 0,
      JSON.stringify(validated.webhook_ids),
      validated.enabled ? 1 : 0,
      id
    );

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
        // Sale already processed for this rule
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

  getAlertsByUserId(userId: number, limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(userId.toString(), limit, offset) as any[];
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    }));
  }

  getAlertByIdForUser(alertId: number, userId: number): Alert | null {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.id = ? AND r.user_id = ?
    `);
    const row = stmt.get(alertId, userId.toString()) as any;
    
    if (!row) return null;

    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    };
  }

  getAlertsByRuleIdForUser(ruleId: number, userId: number, limit: number = 50, offset: number = 0): Alert[] {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.rule_id = ? AND r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(ruleId, userId.toString(), limit, offset) as any[];
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    }));
  }

  getUserStats(userId: number) {
    const userRulesCount = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE user_id = ?').get(userId.toString()) as { count: number };
    const enabledRulesCount = this.db.prepare('SELECT COUNT(*) as count FROM rules WHERE user_id = ? AND enabled = 1').get(userId.toString()) as { count: number };
    const userAlertsCount = this.db.prepare(`
      SELECT COUNT(*) as count FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ?
    `).get(userId.toString()) as { count: number };
    const todayUserAlerts = this.db.prepare(`
      SELECT COUNT(*) as count FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ? AND DATE(a.sent_at) = DATE('now')
    `).get(userId.toString()) as { count: number };

    return {
      totalRules: userRulesCount.count,
      enabledRules: enabledRulesCount.count,
      totalAlerts: userAlertsCount.count,
      todayAlerts: todayUserAlerts.count,
    };
  }

  // Utility methods
  isProcessed(saleId: string, ruleId?: number): boolean {
    if (ruleId) {
      // Check if this specific rule has already processed this sale
      const stmt = this.db.prepare('SELECT 1 FROM alerts WHERE sale_id = ? AND rule_id = ? LIMIT 1');
      return stmt.get(saleId, ruleId) !== undefined;
    } else {
      // Legacy behavior: check globally (for backward compatibility)
      const stmt = this.db.prepare('SELECT 1 FROM alerts WHERE sale_id = ? LIMIT 1');
      return stmt.get(saleId) !== undefined;
    }
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

  // Cleanup old alerts for a specific user (keep last 7 days)
  cleanupUserOldAlerts(userId: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-7 days')
        AND rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `);
    const result = stmt.run(userId.toString());
    return result.changes;
  }

  // Delete all alerts for a specific user
  deleteAllUserAlerts(userId: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `);
    const result = stmt.run(userId.toString());
    return result.changes;
  }

  // Cleanup old alerts globally (admin only - keep last 30 days)
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
    const validated = CreateUserSchema.parse(user);
    
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

    const validatedUpdates = CreateUserSchema.partial().parse(updates);
    
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

  // Webhook encryption utilities
  private encryptWebhookUrl(url: string): string {
    const secretKey = appConfig.JWT_SECRET;
    
    try {
      // Use a more explicit encoding approach
      const encrypted = CryptoJS.AES.encrypt(url, secretKey);
      return encrypted.toString();
    } catch (error) {
      console.error('Webhook encryption failed:', error instanceof Error ? error.message : error);
      throw new Error('Failed to encrypt webhook URL');
    }
  }

  private decryptWebhookUrl(encryptedUrl: string): string {
    const secretKey = appConfig.JWT_SECRET;
    
    if (!encryptedUrl || !secretKey) {
      console.warn('Missing encrypted URL or secret key');
      return '';
    }
    
    try {
      const bytes = CryptoJS.AES.decrypt(encryptedUrl, secretKey);
      
      if (!bytes || bytes.words.length === 0) {
        console.warn('Decryption returned empty bytes - wrong key or corrupted data');
        return '';
      }
      
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      
      // Validate that we got a proper URL back
      if (!decrypted || decrypted.length === 0) {
        console.warn('Decrypted string is empty');
        return '';
      }
      
      if (!decrypted.startsWith('http')) {
        console.warn('Decrypted string is not a valid URL:', decrypted.substring(0, 20));
        return '';
      }
      
      return decrypted;
    } catch (error) {
      console.error('Webhook decryption failed:', error instanceof Error ? error.message : error);
      return '';
    }
  }

  // User webhook CRUD operations
  createUserWebhook(userId: number, webhook: CreateUserWebhook): UserWebhook {
    const validated = CreateUserWebhookSchema.parse(webhook);
    const encryptedUrl = this.encryptWebhookUrl(validated.webhook_url);
    
    const stmt = this.db.prepare(`
      INSERT INTO user_webhooks (user_id, name, webhook_url_encrypted, webhook_type, is_active)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      userId,
      validated.name,
      encryptedUrl,
      validated.webhook_type,
      validated.is_active ? 1 : 0
    );

    return this.getUserWebhookById(result.lastInsertRowid as number)!;
  }

  getUserWebhookById(id: number, decrypt: boolean = false): UserWebhook | null {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE id = ?');
    const row = stmt.get(id) as any;
    
    if (!row) return null;

    const webhook: UserWebhook = {
      ...row,
      is_active: Boolean(row.is_active),
    };

    if (decrypt && webhook.webhook_url_encrypted) {
      webhook.webhook_url = this.decryptWebhookUrl(webhook.webhook_url_encrypted);
    }

    return webhook;
  }

  getUserWebhooksByUserId(userId: number, decrypt: boolean = false): UserWebhook[] {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE user_id = ? ORDER BY created_at DESC');
    const rows = stmt.all(userId) as any[];
    
    return rows.map(row => {
      const webhook: UserWebhook = {
        ...row,
        is_active: Boolean(row.is_active),
      };

      if (decrypt && webhook.webhook_url_encrypted) {
        webhook.webhook_url = this.decryptWebhookUrl(webhook.webhook_url_encrypted);
      }

      return webhook;
    });
  }

  updateUserWebhook(id: number, userId: number, updates: Partial<CreateUserWebhook>): UserWebhook {
    const currentWebhook = this.getUserWebhookById(id);
    if (!currentWebhook || currentWebhook.user_id !== userId) {
      throw new Error('Webhook not found or access denied');
    }

    const validatedUpdates = CreateUserWebhookSchema.partial().parse(updates);
    
    const fields: string[] = [];
    const values: any[] = [];

    if (validatedUpdates.name) {
      fields.push('name = ?');
      values.push(validatedUpdates.name);
    }

    if (validatedUpdates.webhook_url) {
      fields.push('webhook_url_encrypted = ?');
      values.push(this.encryptWebhookUrl(validatedUpdates.webhook_url));
    }

    if (validatedUpdates.webhook_type) {
      fields.push('webhook_type = ?');
      values.push(validatedUpdates.webhook_type);
    }

    if (validatedUpdates.is_active !== undefined) {
      fields.push('is_active = ?');
      values.push(validatedUpdates.is_active ? 1 : 0);
    }

    if (fields.length === 0) {
      return currentWebhook;
    }

    fields.push('updated_at = CURRENT_TIMESTAMP');
    
    const stmt = this.db.prepare(`
      UPDATE user_webhooks 
      SET ${fields.join(', ')}
      WHERE id = ? AND user_id = ?
    `);

    stmt.run(...values, id, userId);
    return this.getUserWebhookById(id)!;
  }

  deleteUserWebhook(id: number, userId: number): boolean {
    const deleteWebhookStmt = this.db.prepare('DELETE FROM user_webhooks WHERE id = ? AND user_id = ?');
    const result = deleteWebhookStmt.run(id, userId);
    
    if (result.changes > 0) {
      // Clean up rules that reference this webhook
      this.cleanupRulesAfterWebhookDeletion(id, userId);
    }
    
    return result.changes > 0;
  }

  private cleanupRulesAfterWebhookDeletion(webhookId: number, userId: number): void {
    // Get all rules for this user that might reference the deleted webhook
    const getRulesStmt = this.db.prepare('SELECT id, webhook_ids FROM rules WHERE user_id = ?');
    const rules = getRulesStmt.all(userId) as any[];

    for (const rule of rules) {
      try {
        const webhookIds = JSON.parse(rule.webhook_ids) as number[];
        const updatedWebhookIds = webhookIds.filter(id => id !== webhookId);
        
        if (updatedWebhookIds.length !== webhookIds.length) {
          if (updatedWebhookIds.length === 0) {
            // If no webhooks remain, disable the rule but keep it
            const updateStmt = this.db.prepare('UPDATE rules SET enabled = 0, webhook_ids = ? WHERE id = ?');
            updateStmt.run(JSON.stringify([]), rule.id);
            console.log(`Disabled rule ${rule.id} - no webhooks remaining after webhook ${webhookId} deletion`);
          } else {
            // Update with remaining webhook IDs
            const updateStmt = this.db.prepare('UPDATE rules SET webhook_ids = ? WHERE id = ?');
            updateStmt.run(JSON.stringify(updatedWebhookIds), rule.id);
            console.log(`Updated rule ${rule.id} - removed webhook ${webhookId}`);
          }
        }
      } catch (error) {
        console.error(`Error cleaning up rule ${rule.id} after webhook deletion:`, error);
      }
    }
  }

  getUserActiveWebhooks(userId: number): UserWebhook[] {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE user_id = ? AND is_active = 1 ORDER BY created_at DESC');
    const rows = stmt.all(userId) as any[];
    
    return rows.map(row => ({
      ...row,
      is_active: Boolean(row.is_active),
      webhook_url: this.decryptWebhookUrl(row.webhook_url_encrypted), // Decrypt for use
    }));
  }

  // Get rule webhooks with decrypted URLs (for notifications)
  getRuleWebhooksForNotification(ruleId: number): UserWebhook[] {
    const rule = this.getRuleById(ruleId);
    if (!rule || !rule.webhook_ids?.length) return [];

    const placeholders = rule.webhook_ids.map(() => '?').join(',');
    const stmt = this.db.prepare(`
      SELECT * FROM user_webhooks 
      WHERE id IN (${placeholders}) AND is_active = 1
    `);
    const rows = stmt.all(...rule.webhook_ids) as any[];
    
    return rows
      .map(row => ({
        ...row,
        is_active: Boolean(row.is_active),
        webhook_url: this.decryptWebhookUrl(row.webhook_url_encrypted),
      }))
      .filter(webhook => webhook.webhook_url && webhook.webhook_url.length > 0); // Filter out failed decryptions
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