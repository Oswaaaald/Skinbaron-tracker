import Database from 'better-sqlite3';
import { z } from 'zod';
import { appConfig } from './config.js';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import crypto from 'crypto';
import { migrationLogger } from './migration-logger.js';

/**
 * DELETION POLICY
 * ===============
 * All user deletions are handled by database CASCADE constraints.
 * 
 * Rules:
 * - Personal data (rules, alerts, webhooks, audit logs) → CASCADE (deleted with user)
 * - Admin actions performed by user → CASCADE (deleted with admin)
 * - Admin actions targeting user → CASCADE (deleted with target)
 * 
 * To add a new feature:
 * 1. Add FOREIGN KEY with appropriate ON DELETE action (CASCADE or SET NULL)
 * 2. No code change needed in deleteUser() - it only deletes the user record
 * 3. Test user deletion to verify cascade behavior
 */

// Schema validation with Zod
export const RuleSchema = z.object({
  id: z.number().optional(),
  user_id: z.number().int().positive(),
  search_item: z.string().min(1, 'Search item is required'),
  min_price: z.number().min(0).optional(),
  max_price: z.number().min(0).optional(),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  souvenir_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  allow_stickers: z.boolean().default(true),
  webhook_ids: z.array(z.number()).min(0).default([]),
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
  totp_secret_encrypted: z.string().nullable().optional(),
  totp_enabled: z.number().optional(),
  recovery_codes_encrypted: z.string().nullable().optional(),
});

export const UserSchema = z.object({
  id: z.number(),
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  is_admin: z.number().default(0),
  is_super_admin: z.number().default(0),
  is_approved: z.number().default(0),
  totp_secret_encrypted: z.string().nullable().optional(),
  totp_enabled: z.number().default(0).optional(),
  recovery_codes_encrypted: z.string().nullable().optional(),
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
export type User = z.infer<typeof UserSchema> & {
  totp_secret?: string | null;      // Decrypted (not stored)
  recovery_codes?: string | null;   // Decrypted (not stored)
};
export type CreateUser = z.infer<typeof CreateUserSchema>;
export type CreateRule = Omit<Rule, 'id' | 'created_at' | 'updated_at'>;
export type CreateAlert = Omit<Alert, 'id' | 'sent_at'>;

export type UserWebhook = z.infer<typeof UserWebhookSchema> & {
  webhook_url?: string; // Decrypted URL (not stored)
};
export type CreateUserWebhook = z.infer<typeof CreateUserWebhookSchema>;

export type RefreshTokenRecord = {
  id: number;
  user_id: number;
  token_hash: string;
  token_jti: string;
  expires_at: string;
  revoked_at?: string | null;
  replaced_by_jti?: string | null;
  created_at: string;
};

export type AccessTokenBlacklistRecord = {
  jti: string;
  user_id: number;
  expires_at: string;
  reason?: string | null;
  created_at: string;
};

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
  }

  /**
   * Helper method to execute a query that returns a single row
   * @param sql SQL query string
   * @param params Query parameters
   * @returns Single row or undefined
   */
  private query<T>(sql: string, ...params: any[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }

  /**
   * Helper method to execute a query that returns multiple rows
   * @param sql SQL query string
   * @param params Query parameters
   * @returns Array of rows
   */
  private queryAll<T>(sql: string, ...params: any[]): T[] {
    return this.db.prepare(sql).all(...params) as T[];
  }

  /**
   * Helper method to execute a query that modifies data (INSERT, UPDATE, DELETE)
   * @param sql SQL query string
   * @param params Query parameters
   * @returns RunResult with changes, lastInsertRowid, etc.
   */
  private execute(sql: string, ...params: any[]): Database.RunResult {
    return this.db.prepare(sql).run(...params);
  }

  private initializeTables() {
    // Create rules table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        search_item TEXT NOT NULL,
        min_price REAL,
        max_price REAL,
        min_wear REAL CHECK (min_wear >= 0 AND min_wear <= 1),
        max_wear REAL CHECK (max_wear >= 0 AND max_wear <= 1),
        stattrak_filter TEXT DEFAULT 'all' CHECK (stattrak_filter IN ('all', 'only', 'exclude')),
        souvenir_filter TEXT DEFAULT 'all' CHECK (souvenir_filter IN ('all', 'only', 'exclude')),
        allow_stickers BOOLEAN DEFAULT 1,
        webhook_ids TEXT, -- JSON array of webhook IDs
        enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      CREATE INDEX IF NOT EXISTS idx_alerts_rule_sent ON alerts (rule_id, sent_at);
    `);

  }



  private initializeUserTables() {
    // Disable foreign keys during migrations to allow table recreation
    this.db.pragma('foreign_keys = OFF');
    
    try {
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
      CREATE INDEX IF NOT EXISTS idx_audit_log_user_created ON audit_log(user_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);
    `);

    // Migration: Add is_admin column if it doesn't exist
    const hasIsAdmin = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_admin'
    `).get() as { count: number };

    if (hasIsAdmin.count === 0) {
      this.db.exec(`ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0`);
      migrationLogger.info('Migration: Added is_admin column to users table');
    }

    // Migration: Add is_super_admin column if it doesn't exist
    const hasIsSuperAdmin = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_super_admin'
    `).get() as { count: number };

    if (hasIsSuperAdmin.count === 0) {
      this.db.exec(`ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN DEFAULT 0`);
      migrationLogger.info('Migration: Added is_super_admin column to users table');
      
      // Make the first user a super admin if exists
      const firstUser = this.db.prepare('SELECT id FROM users ORDER BY id LIMIT 1').get() as { id: number } | undefined;
      if (firstUser) {
        this.db.prepare('UPDATE users SET is_super_admin = 1, is_admin = 1 WHERE id = ?').run(firstUser.id);
        migrationLogger.info(`Migration: Made first user (ID: ${firstUser.id}) a super admin`);
      }
    }

    // Migration: Add is_approved column if it doesn't exist
    const hasIsApproved = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_approved'
    `).get() as { count: number };

    if (hasIsApproved.count === 0) {
      this.db.exec(`ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 0`);
      migrationLogger.info('Migration: Added is_approved column to users table');
      
      // Approve all existing users
      this.db.prepare('UPDATE users SET is_approved = 1').run();
      migrationLogger.info('Migration: Approved all existing users');
    }

    // Migration: Add new filter columns to rules table if they don't exist
    const hasStattrakFilter = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('rules') WHERE name='stattrak_filter'
    `).get() as { count: number };

    if (hasStattrakFilter.count === 0) {
      // Add new columns
      this.db.exec(`ALTER TABLE rules ADD COLUMN stattrak_filter TEXT DEFAULT 'all'`);
      this.db.exec(`ALTER TABLE rules ADD COLUMN souvenir_filter TEXT DEFAULT 'all'`);
      this.db.exec(`ALTER TABLE rules ADD COLUMN allow_stickers BOOLEAN DEFAULT 1`);
      migrationLogger.info('Migration: Added filter columns to rules table');
      
      // Migrate old boolean stattrak/souvenir values to new filter format
      this.db.exec(`
        UPDATE rules 
        SET stattrak_filter = CASE WHEN stattrak = 1 THEN 'only' ELSE 'all' END,
            souvenir_filter = CASE WHEN souvenir = 1 THEN 'only' ELSE 'all' END
        WHERE stattrak_filter IS NULL OR souvenir_filter IS NULL
      `);
      migrationLogger.info('Migration: Migrated old stattrak/souvenir values to new filter format');
    }

    // Migration: Add 2FA columns if they don't exist
    const hasTotpSecret = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_secret'
    `).get() as { count: number };

    if (hasTotpSecret.count === 0) {
      this.db.exec(`ALTER TABLE users ADD COLUMN totp_secret TEXT`);
      this.db.exec(`ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0`);
      this.db.exec(`ALTER TABLE users ADD COLUMN recovery_codes TEXT`);
      migrationLogger.info('Migration: Added 2FA columns to users table');
    }

    // Migration: Add encrypted 2FA columns and migrate existing data
    const hasEncryptedSecret = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_secret_encrypted'
    `).get() as { count: number };

    if (hasEncryptedSecret.count === 0) {
      this.db.exec(`ALTER TABLE users ADD COLUMN totp_secret_encrypted TEXT`);
      this.db.exec(`ALTER TABLE users ADD COLUMN recovery_codes_encrypted TEXT`);
      
      // Encrypt existing plain-text secrets
      const usersWithTotp = this.db.prepare(`
        SELECT id, totp_secret, recovery_codes 
        FROM users 
        WHERE (totp_secret IS NOT NULL AND totp_secret != '') 
           OR (recovery_codes IS NOT NULL AND recovery_codes != '')
      `).all() as any[];

      let encryptedCount = 0;
      for (const user of usersWithTotp) {
        if (user.totp_secret) {
          const encryptedSecret = this.encryptData(user.totp_secret);
          this.db.prepare(`
            UPDATE users 
            SET totp_secret_encrypted = ?, totp_secret = NULL 
            WHERE id = ?
          `).run(encryptedSecret, user.id);
        }
        if (user.recovery_codes) {
          const encryptedCodes = this.encryptData(user.recovery_codes);
          this.db.prepare(`
            UPDATE users 
            SET recovery_codes_encrypted = ?, recovery_codes = NULL 
            WHERE id = ?
          `).run(encryptedCodes, user.id);
        }
        encryptedCount++;
      }
      
      if (encryptedCount > 0) {
        migrationLogger.info(`Migration: Encrypted 2FA secrets for ${encryptedCount} users`);
      }
    }

    // Migration: Drop legacy plaintext 2FA columns
    // IMPORTANT: This migration is DISABLED to prevent data loss in production
    // The legacy columns (totp_secret, recovery_codes) will remain NULL but won't be dropped
    // to avoid triggering CASCADE DELETE on foreign key relationships
    const hasLegacyTotpSecret = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_secret'
    `).get() as { count: number };

    if (hasLegacyTotpSecret.count > 0) {
      migrationLogger.info('Migration: Legacy 2FA columns detected but NOT dropped to preserve data integrity');
      migrationLogger.info('Columns totp_secret and recovery_codes are NULL and unused, only encrypted columns are active');
    }

    // Migration: Create audit_log table if it doesn't exist
    const hasAuditLog = this.db.prepare(`
      SELECT COUNT(*) as count FROM sqlite_master WHERE type='table' AND name='audit_log'
    `).get() as { count: number };

    if (hasAuditLog.count === 0) {
      this.db.exec(`
        CREATE TABLE audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          event_type TEXT NOT NULL,
          event_data TEXT,
          ip_address TEXT,
          user_agent TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
        CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
        CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
      `);
      migrationLogger.info('Migration: Created audit_log table');
    }

    // Create admin actions audit log table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS admin_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        target_user_id INTEGER,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_admin_actions_admin ON admin_actions(admin_user_id);
      CREATE INDEX IF NOT EXISTS idx_admin_actions_created ON admin_actions(created_at);
    `);

    // Token tables for refresh + blacklist support
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        token_jti TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        revoked_at DATETIME,
        replaced_by_jti TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked_at);
    `);

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS access_token_blacklist (
        jti TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at DATETIME NOT NULL,
        reason TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_token_blacklist_expiry ON access_token_blacklist(expires_at);
      CREATE INDEX IF NOT EXISTS idx_token_blacklist_user ON access_token_blacklist(user_id);
    `);

    // Migration: Add FK constraint on target_user_id if not exists
    const hasTargetUserFK = this.db.prepare(`
      SELECT COUNT(*) as count FROM pragma_foreign_key_list('admin_actions')
      WHERE "from" = 'target_user_id'
    `).get() as { count: number };

    if (hasTargetUserFK.count === 0) {
      migrationLogger.info('Migration: Adding FK constraint on admin_actions.target_user_id');
      
      // SQLite doesn't support ALTER TABLE ADD CONSTRAINT, so we need to recreate the table
      this.db.exec(`
        -- Create new table with FK constraint
        CREATE TABLE admin_actions_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          admin_user_id INTEGER NOT NULL,
          action TEXT NOT NULL,
          target_user_id INTEGER,
          details TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (admin_user_id) REFERENCES users(id) ON DELETE CASCADE,
          FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        -- Copy existing data
        INSERT INTO admin_actions_new (id, admin_user_id, action, target_user_id, details, created_at)
        SELECT id, admin_user_id, action, target_user_id, details, created_at
        FROM admin_actions;

        -- Drop old table
        DROP TABLE admin_actions;

        -- Rename new table
        ALTER TABLE admin_actions_new RENAME TO admin_actions;

        -- Recreate indexes
        CREATE INDEX idx_admin_actions_admin ON admin_actions(admin_user_id);
        CREATE INDEX idx_admin_actions_created ON admin_actions(created_at);
      `);
      
      migrationLogger.info('Migration: FK constraint added successfully');
    }

    // Migration: Ensure rules.user_id column uses INTEGER type
    const userIdColumn = this.db.prepare(`
      SELECT type FROM pragma_table_info('rules') WHERE name='user_id'
    `).get() as { type?: string } | undefined;

    if (userIdColumn && userIdColumn.type && userIdColumn.type.toUpperCase() !== 'INTEGER') {
      migrationLogger.info('Migration: Rebuilding rules table to use INTEGER user_id');

      this.db.exec(`
        DROP TABLE IF EXISTS rules_type_fix;

        CREATE TABLE rules_type_fix (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          search_item TEXT NOT NULL,
          min_price REAL,
          max_price REAL,
          min_wear REAL CHECK (min_wear >= 0 AND min_wear <= 1),
          max_wear REAL CHECK (max_wear >= 0 AND max_wear <= 1),
          stattrak_filter TEXT DEFAULT 'all' CHECK (stattrak_filter IN ('all', 'only', 'exclude')),
          souvenir_filter TEXT DEFAULT 'all' CHECK (souvenir_filter IN ('all', 'only', 'exclude')),
          allow_stickers BOOLEAN DEFAULT 1,
          webhook_ids TEXT,
          enabled BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        INSERT INTO rules_type_fix (id, user_id, search_item, min_price, max_price, min_wear, max_wear,
                                     stattrak_filter, souvenir_filter, allow_stickers, webhook_ids, enabled,
                                     created_at, updated_at)
        SELECT id, user_id, search_item, min_price, max_price, min_wear, max_wear,
               stattrak_filter, souvenir_filter, allow_stickers, webhook_ids, enabled,
               created_at, updated_at
        FROM rules;

        DROP TABLE rules;
        ALTER TABLE rules_type_fix RENAME TO rules;

        CREATE INDEX IF NOT EXISTS idx_rules_user_id ON rules(user_id);
        CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
      `);

      migrationLogger.info('Migration: rules.user_id now INTEGER with enforced FK');
    }

    // Migration: Add CASCADE delete for orphaned data
    // Check if we need to migrate rules table to add user_id constraint
    const hasUserIdConstraint = this.db.prepare(`
      SELECT sql FROM sqlite_master WHERE type='table' AND name='rules'
    `).get() as { sql: string } | undefined;

    const needsRulesConstraint = hasUserIdConstraint && !hasUserIdConstraint.sql.includes('FOREIGN KEY');

    if (needsRulesConstraint) {
      migrationLogger.info('Migration: Adding CASCADE constraints to rules table...');
      
      try {
        // SQLite doesn't support ALTER TABLE for foreign keys, so we need to recreate the table
        this.db.exec(`
          -- Drop rules_new if it exists from a previous failed migration
          DROP TABLE IF EXISTS rules_new;

          -- Create new rules table with proper constraints
          CREATE TABLE rules_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            search_item TEXT NOT NULL,
            min_price REAL,
            max_price REAL,
            min_wear REAL CHECK (min_wear >= 0 AND min_wear <= 1),
            max_wear REAL CHECK (max_wear >= 0 AND max_wear <= 1),
            stattrak_filter TEXT DEFAULT 'all' CHECK (stattrak_filter IN ('all', 'only', 'exclude')),
            souvenir_filter TEXT DEFAULT 'all' CHECK (souvenir_filter IN ('all', 'only', 'exclude')),
            allow_stickers BOOLEAN DEFAULT 1,
            webhook_ids TEXT,
            enabled BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          );

          -- Copy data from old table (only rules for existing users)
          INSERT INTO rules_new (id, user_id, search_item, min_price, max_price, min_wear, max_wear, 
                                 stattrak_filter, souvenir_filter, allow_stickers, webhook_ids, enabled, 
                                 created_at, updated_at)
          SELECT id, user_id, search_item, min_price, max_price, min_wear, max_wear, 
                 stattrak_filter, souvenir_filter, allow_stickers, webhook_ids, enabled, 
                 created_at, updated_at
          FROM rules 
          WHERE CAST(user_id AS INTEGER) IN (SELECT id FROM users);

          -- Drop old table
          DROP TABLE rules;

          -- Rename new table
          ALTER TABLE rules_new RENAME TO rules;

          -- Recreate indexes
          CREATE INDEX idx_rules_user_id ON rules (user_id);
          CREATE INDEX idx_rules_enabled ON rules (enabled);
        `);

        migrationLogger.info('Migration: Added CASCADE constraints to rules table');
      } catch (error: any) {
        migrationLogger.error('Migration failed:', error);
        throw error;
      }
    }
    
    } finally {
      // Re-enable foreign keys after all migrations
      this.db.pragma('foreign_keys = ON');
      migrationLogger.info('Foreign keys re-enabled');
    }
  }

  // Rules CRUD operations
  createRule(rule: CreateRule): Rule {
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
        migrationLogger.warn('Failed to parse webhook_ids for rule', { ruleId: row.id, error });
      }
    }
    
    return {
      ...row,
      stattrak_filter: row.stattrak_filter ?? 'all',
      souvenir_filter: row.souvenir_filter ?? 'all',
      allow_stickers: Boolean(row.allow_stickers),
      enabled: Boolean(row.enabled),
      webhook_ids: webhookIds,
    };
  }getAllRules(): Rule[] {
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
          migrationLogger.warn('Failed to parse webhook_ids in getAllRules', { ruleId: row.id });
        }
      }
      
      return {
        ...row,
        stattrak_filter: row.stattrak_filter ?? 'all',
        souvenir_filter: row.souvenir_filter ?? 'all',
        allow_stickers: Boolean(row.allow_stickers),
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
          migrationLogger.warn('Failed to parse webhook_ids in getRulesByUserId', { ruleId: row.id, userId: row.user_id });
        }
      }
      
      return {
        ...row,
        user_id: row.user_id, // Keep original format for now
        stattrak_filter: row.stattrak_filter ?? 'all',
        souvenir_filter: row.souvenir_filter ?? 'all',
        allow_stickers: Boolean(row.allow_stickers),
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
          migrationLogger.warn('Failed to parse webhook_ids in getEnabledRules', { ruleId: row.id });
        }
      }
      
      return {
        ...row,
        stattrak_filter: row.stattrak_filter ?? 'all',
        souvenir_filter: row.souvenir_filter ?? 'all',
        allow_stickers: Boolean(row.allow_stickers),
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
          stattrak_filter = ?, souvenir_filter = ?, allow_stickers = ?, webhook_ids = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run(
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
    const rows = this.queryAll<any>(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `, userId.toString(), limit, offset);
    
    return rows.map(row => ({
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    }));
  }

  getAlertByIdForUser(alertId: number, userId: number): Alert | null {
    const row = this.query<any>(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.id = ? AND r.user_id = ?
    `, alertId, userId.toString());
    
    if (!row) return null;

    return {
      ...row,
      stattrak: Boolean(row.stattrak),
      souvenir: Boolean(row.souvenir),
    };
  }

  getAlertsByRuleIdForUser(ruleId: number, userId: number, limit: number = 50, offset: number = 0): Alert[] {
    const rows = this.queryAll<any>(`
      SELECT a.* FROM alerts a 
      JOIN rules r ON a.rule_id = r.id 
      WHERE a.rule_id = ? AND r.user_id = ? 
      ORDER BY a.sent_at DESC 
      LIMIT ? OFFSET ?
    `, ruleId, userId.toString(), limit, offset);
    
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
    const result = this.execute(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-7 days')
        AND rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `, userId.toString());
    return result.changes;
  }

  // Delete all alerts for a specific user
  deleteAllUserAlerts(userId: number): number {
    const result = this.execute(`
      DELETE FROM alerts 
      WHERE rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `, userId.toString());
    return result.changes;
  }

  // Cleanup old alerts globally (admin only - keep last 30 days)
  cleanupOldAlerts(): number {
    const result = this.execute(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-30 days')
    `);
    return result.changes;
  }

  // User management methods
  createUser(user: CreateUser): User {
    const validated = CreateUserSchema.parse(user);
    
    const stmt = this.db.prepare(`
      INSERT INTO users (username, email, password_hash, is_approved)
      VALUES (?, ?, ?, 0)
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

  // Helper to decrypt 2FA secrets in user object
  private decrypt2FASecrets(user: User): User {
    if (user.totp_secret_encrypted) {
      user.totp_secret = this.decryptData(user.totp_secret_encrypted);
    }
    if (user.recovery_codes_encrypted) {
      user.recovery_codes = this.decryptData(user.recovery_codes_encrypted);
    }
    return user;
  }

  getUserById(id: number): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE id = ?');
    const row = stmt.get(id) as any;
    if (!row) return null;
    const user = UserSchema.parse(row);
    return this.decrypt2FASecrets(user);
  }

  getUserByEmail(email: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE email = ?');
    const row = stmt.get(email) as any;
    if (!row) return null;
    const user = UserSchema.parse(row);
    return this.decrypt2FASecrets(user);
  }

  getUserByUsername(username: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE username = ?');
    const row = stmt.get(username) as any;
    if (!row) return null;
    const user = UserSchema.parse(row);
    return this.decrypt2FASecrets(user);
  }

  updateUser(id: number, updates: Partial<CreateUser> & { totp_secret?: string | null, recovery_codes?: string | null }): User {
    const currentUser = this.getUserById(id);
    if (!currentUser) {
      throw new Error('User not found');
    }

    // Convert plaintext 2FA fields to encrypted versions
    const processedUpdates: any = { ...updates };
    
    // Handle totp_secret encryption
    if ('totp_secret' in updates) {
      if (updates.totp_secret) {
        processedUpdates.totp_secret_encrypted = this.encryptData(updates.totp_secret);
      } else {
        processedUpdates.totp_secret_encrypted = null;
      }
      delete processedUpdates.totp_secret;
    }
    
    // Handle recovery_codes encryption
    if ('recovery_codes' in updates) {
      if (updates.recovery_codes) {
        processedUpdates.recovery_codes_encrypted = this.encryptData(updates.recovery_codes);
      } else {
        processedUpdates.recovery_codes_encrypted = null;
      }
      delete processedUpdates.recovery_codes;
    }

    const validatedUpdates = CreateUserSchema.partial().parse(processedUpdates);
    
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
    
    // Invalidate user cache after update
    import('./middleware.js').then(({ invalidateUserCache }) => {
      invalidateUserCache(id);
    }).catch(() => {});
    
    return this.getUserById(id)!;
  }

  deleteUser(id: number): boolean {
    // Prevent deletion of super admin
    const user = this.getUserById(id);
    if (user?.is_super_admin) {
      throw new Error('Cannot delete super admin');
    }
    
    // Delete user - CASCADE constraints handle all related data:
    // - rules (and their alerts via rule_id CASCADE)
    // - user_webhooks
    // - audit_log
    // - admin_actions (both as admin and as target)
    try {
      const result = this.execute('DELETE FROM users WHERE id = ?', id);
      
      // Invalidate user cache after deletion
      if (result.changes > 0) {
        import('./middleware.js').then(({ invalidateUserCache }) => {
          invalidateUserCache(id);
        }).catch(() => {});
      }
      
      return result.changes > 0;
    } catch (error: any) {
      migrationLogger.error('Error deleting user:', {
        message: error.message,
        code: error.code,
        userId: id
      });
      throw error;
    }
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  // Generic encryption utilities (used for webhooks and 2FA secrets)
  private encryptData(data: string): string {
    const secretKey = appConfig.ENCRYPTION_KEY;
    
    if (!secretKey) {
      throw new Error('ENCRYPTION_KEY not configured');
    }
    
    try {
      // Use a static salt for key derivation (or store per-entry salt for even better security)
      const salt = crypto.createHash('sha256').update('skinbaron-alerts-salt-v1').digest();
      // Derive key from ENCRYPTION_KEY using PBKDF2 (100,000 iterations)
      const key = crypto.pbkdf2Sync(secretKey, salt, 100000, 32, 'sha256');
      const iv = crypto.randomBytes(16);
      
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Return IV + encrypted data
      return iv.toString('hex') + ':' + encrypted;
    } catch (error) {
      throw new Error('Failed to encrypt data');
    }
  }

  private decryptData(encryptedData: string): string {
    const secretKey = appConfig.ENCRYPTION_KEY;
    
    if (!encryptedData || !secretKey) {
      return '';
    }
    
    try {
      // Split IV and encrypted data
      const parts = encryptedData.split(':');
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return '';
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const encryptedText = parts[1];
      
      // Use same salt as encryption
      const salt = crypto.createHash('sha256').update('skinbaron-alerts-salt-v1').digest();
      // Derive key from ENCRYPTION_KEY using PBKDF2 (100,000 iterations)
      const key = crypto.pbkdf2Sync(secretKey, salt, 100000, 32, 'sha256');
      
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      return '';
    }
  }

  // Refresh token management
  addRefreshToken(userId: number, token: string, tokenJti: string, expiresAt: number): RefreshTokenRecord {
    const tokenHash = this.hashToken(token);
    const stmt = this.db.prepare(`
      INSERT INTO refresh_tokens (user_id, token_hash, token_jti, expires_at)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(userId, tokenHash, tokenJti, new Date(expiresAt).toISOString());
    return this.getRefreshTokenByHash(tokenHash)!;
  }

  getRefreshTokenByHash(tokenHash: string): RefreshTokenRecord | null {
    const row = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash) as any;
    if (!row) return null;
    return row as RefreshTokenRecord;
  }

  getRefreshToken(token: string): RefreshTokenRecord | null {
    const tokenHash = this.hashToken(token);
    return this.getRefreshTokenByHash(tokenHash);
  }

  revokeRefreshToken(token: string, replacedByJti?: string) {
    const tokenHash = this.hashToken(token);
    this.db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), replaced_by_jti = COALESCE(?, replaced_by_jti)
      WHERE token_hash = ?
    `).run(replacedByJti ?? null, tokenHash);
  }

  revokeAllRefreshTokensForUser(userId: number) {
    this.db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = CURRENT_TIMESTAMP, replaced_by_jti = COALESCE(replaced_by_jti, 'logout_all')
      WHERE user_id = ? AND revoked_at IS NULL
    `).run(userId);
  }

  cleanupRefreshTokens() {
    this.db.prepare(`
      DELETE FROM refresh_tokens
      WHERE (revoked_at IS NOT NULL) OR (expires_at < CURRENT_TIMESTAMP)
    `).run();
  }

  // Access token blacklist helpers
  blacklistAccessToken(jti: string, userId: number, expiresAt: number, reason?: string) {
    this.db.prepare(`
      INSERT INTO access_token_blacklist (jti, user_id, expires_at, reason)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at, reason = COALESCE(excluded.reason, access_token_blacklist.reason)
    `).run(jti, userId, new Date(expiresAt).toISOString(), reason ?? null);
  }

  isAccessTokenBlacklisted(jti: string): boolean {
    this.db.prepare(`
      DELETE FROM access_token_blacklist WHERE expires_at < CURRENT_TIMESTAMP
    `).run();

    const row = this.db.prepare('SELECT 1 FROM access_token_blacklist WHERE jti = ?').get(jti) as any;
    return Boolean(row);
  }

  // Webhook encryption utilities (using generic methods)
  private encryptWebhookUrl(url: string): string {
    return this.encryptData(url);
  }

  private decryptWebhookUrl(encryptedUrl: string): string {
    return this.decryptData(encryptedUrl);
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
          } else {
            // Update with remaining webhook IDs
            const updateStmt = this.db.prepare('UPDATE rules SET webhook_ids = ? WHERE id = ?');
            updateStmt.run(JSON.stringify(updatedWebhookIds), rule.id);
          }
        }
      } catch (error) {
        migrationLogger.warn('Failed to cleanup rule after webhook deletion', { 
          ruleId: rule.id, 
          webhookId, 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
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

    // Build parameterized query with proper placeholders
    const placeholders = rule.webhook_ids.map(() => '?').join(',');
    const query = `SELECT * FROM user_webhooks WHERE id IN (${placeholders}) AND is_active = 1`;
    const stmt = this.db.prepare(query);
    const rows = stmt.all(...rule.webhook_ids) as any[];
    
    return rows
      .map(row => ({
        ...row,
        is_active: Boolean(row.is_active),
        webhook_url: this.decryptWebhookUrl(row.webhook_url_encrypted),
      }))
      .filter(webhook => webhook.webhook_url && webhook.webhook_url.length > 0); // Filter out failed decryptions
  }

  // Admin methods
  getAllUsers() {
    const stmt = this.db.prepare('SELECT id, username, email, is_admin, is_super_admin, is_approved, created_at, updated_at FROM users WHERE is_approved = 1 ORDER BY created_at DESC');
    return stmt.all() as Array<{
      id: number;
      username: string;
      email: string;
      is_admin: number;
      is_super_admin: number;
      is_approved: number;
      created_at: string;
      updated_at: string;
    }>;
  }

  searchUsers(query: string) {
    const searchTerm = `%${query}%`;
    const stmt = this.db.prepare('SELECT id, username, email FROM users WHERE is_approved = 1 AND (username LIKE ? OR email LIKE ?) ORDER BY username ASC LIMIT 20');
    return stmt.all(searchTerm, searchTerm) as Array<{
      id: number;
      username: string;
      email: string;
    }>;
  }

  getPendingUsers() {
    const stmt = this.db.prepare('SELECT id, username, email, created_at FROM users WHERE is_approved = 0 ORDER BY created_at DESC');
    return stmt.all() as Array<{
      id: number;
      username: string;
      email: string;
      created_at: string;
    }>;
  }

  approveUser(userId: number): boolean {
    const stmt = this.db.prepare('UPDATE users SET is_approved = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?');
    const result = stmt.run(userId);
    return result.changes > 0;
  }

  rejectUser(userId: number): boolean {
    // Reject = delete the user
    return this.deleteUser(userId);
  }

  getUserRules(userId: number) {
    return this.getRulesByUserId(userId);
  }

  getUserAlerts(userId: number) {
    const stmt = this.db.prepare(`
      SELECT a.* FROM alerts a
      INNER JOIN rules r ON a.rule_id = r.id
      WHERE r.user_id = ?
      ORDER BY a.sent_at DESC
    `);
    return stmt.all(userId.toString()) as Alert[];
  }

  getUserWebhooks(userId: number) {
    const stmt = this.db.prepare('SELECT * FROM user_webhooks WHERE user_id = ?');
    return stmt.all(userId.toString()) as UserWebhook[];
  }

  toggleUserAdmin(userId: number, isAdmin: boolean): boolean {
    try {
      // Check if user is super admin - they cannot be demoted
      const user = this.getUserById(userId);
      if (user?.is_super_admin && !isAdmin) {
        throw new Error('Cannot revoke admin status from super admin');
      }
      
      const stmt = this.db.prepare('UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?');
      const result = stmt.run(isAdmin ? 1 : 0, new Date().toISOString(), userId);
      
      // Invalidate user cache after admin status change
      if (result.changes > 0) {
        import('./middleware.js').then(({ invalidateUserCache }) => {
          invalidateUserCache(userId);
        }).catch(() => {});
      }
      
      return result.changes > 0;
    } catch (error) {
      migrationLogger.error('Error toggling user admin:', error);
      throw error;
    }
  }

  getGlobalStats() {
    const usersStmt = this.db.prepare('SELECT COUNT(*) as count FROM users WHERE is_approved = 1');
    const rulesStmt = this.db.prepare('SELECT COUNT(*) as count FROM rules');
    const alertsStmt = this.db.prepare('SELECT COUNT(*) as count FROM alerts');
    const webhooksStmt = this.db.prepare('SELECT COUNT(*) as count FROM user_webhooks');
    const adminsStmt = this.db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 1 AND is_approved = 1');

    return {
      total_users: (usersStmt.get() as any).count,
      total_admins: (adminsStmt.get() as any).count,
      total_rules: (rulesStmt.get() as any).count,
      total_alerts: (alertsStmt.get() as any).count,
      total_webhooks: (webhooksStmt.get() as any).count,
    };
  }

  logAdminAction(adminUserId: number, action: string, targetUserId: number | null, details: string) {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO admin_actions (admin_user_id, action, target_user_id, details, created_at)
        VALUES (?, ?, ?, ?, ?)
      `);
      stmt.run(adminUserId, action, targetUserId, details, new Date().toISOString());
    } catch (error) {
      migrationLogger.error('Error logging admin action:', error);
    }
  }

  getAdminLogs(limit: number = 50) {
    const stmt = this.db.prepare(`
      SELECT 
        al.*,
        u1.username as admin_username,
        u2.username as target_username
      FROM admin_actions al
      LEFT JOIN users u1 ON al.admin_user_id = u1.id
      LEFT JOIN users u2 ON al.target_user_id = u2.id
      ORDER BY al.created_at DESC
      LIMIT ?
    `);
    
    return stmt.all(limit) as Array<{
      id: number;
      admin_user_id: number;
      admin_username: string;
      action: string;
      target_user_id: number | null;
      target_username: string | null;
      details: string;
      created_at: string;
    }>;
  }

  close() {
    this.db.close();
  }
  // Audit log methods
  createAuditLog(
    userId: number,
    eventType: string,
    eventData?: string,
    ipAddress?: string,
    userAgent?: string
  ): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log (user_id, event_type, event_data, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(userId, eventType, eventData || null, ipAddress || null, userAgent || null);
  }

  getAuditLogsByUserId(userId: number, limit: number = 100): any[] {
    const stmt = this.db.prepare(`
      SELECT * FROM audit_log 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ?
    `);
    const logs = stmt.all(userId, limit) as any[];
    
    // Enrich logs with admin usernames from event_data
    return logs.map(log => {
      if (log.event_data) {
        try {
          const data = JSON.parse(log.event_data);
          
          // Extract admin_id from various possible fields
          const adminId = data.admin_id || data.approved_by_admin_id || data.deleted_by_admin_id;
          
          if (adminId) {
            const adminStmt = this.db.prepare('SELECT username FROM users WHERE id = ?');
            const admin = adminStmt.get(adminId) as { username: string } | undefined;
            
            if (admin) {
              // Add admin_username to the parsed event_data
              log.event_data = JSON.stringify({
                ...data,
                admin_username: admin.username
              });
            }
          }
        } catch (e) {
          // If event_data is not valid JSON, leave it as is
        }
      }
      return log;
    });
  }

  getAllAuditLogs(limit: number = 100, eventType?: string, userId?: number): any[] {
    let query = `
      SELECT 
        audit_log.*,
        users.username,
        users.email
      FROM audit_log
      LEFT JOIN users ON audit_log.user_id = users.id
      WHERE 1=1
    `;
    const params: any[] = [];

    if (eventType) {
      query += ' AND audit_log.event_type = ?';
      params.push(eventType);
    }

    if (userId) {
      query += ' AND audit_log.user_id = ?';
      params.push(userId);
    }

    query += ' ORDER BY audit_log.created_at DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(query);
    const logs = stmt.all(...params) as any[];
    
    // Enrich logs with admin usernames from event_data
    return logs.map(log => {
      if (log.event_data) {
        try {
          const data = JSON.parse(log.event_data);
          
          // Extract admin_id from various possible fields
          const adminId = data.admin_id || data.approved_by_admin_id || data.deleted_by_admin_id;
          
          if (adminId) {
            const adminStmt = this.db.prepare('SELECT username FROM users WHERE id = ?');
            const admin = adminStmt.get(adminId) as { username: string } | undefined;
            
            if (admin) {
              // Add admin_username to the parsed event_data
              log.event_data = JSON.stringify({
                ...data,
                admin_username: admin.username
              });
            }
          }
        } catch (e) {
          // If event_data is not valid JSON, leave it as is
        }
      }
      return log;
    });
  }

  /**
   * Clean old audit logs according to retention policy (GDPR compliance)
   */
  cleanOldAuditLogs(retentionDays: number): { deleted: number } {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
    const cutoffTimestamp = cutoffDate.toISOString();

    const stmt = this.db.prepare(`
      DELETE FROM audit_log 
      WHERE created_at < ?
    `);
    
    const result = stmt.run(cutoffTimestamp);
    return { deleted: result.changes };
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