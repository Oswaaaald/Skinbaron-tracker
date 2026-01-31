import Database from 'better-sqlite3';
import { appConfig } from '../lib/config.js';
import { migrationLogger } from '../lib/migration-logger.js';

let dbInstance: Database.Database | null = null;

export function getDatabase(): Database.Database {
  if (!dbInstance) {
    dbInstance = new Database(appConfig.SQLITE_PATH);
    
    // Enable WAL mode for better concurrency
    dbInstance.pragma('journal_mode = WAL');
    
    // Enable foreign key constraints
    dbInstance.pragma('foreign_keys = ON');
    
    // Run migrations
    runMigrations(dbInstance);
    
    // Optimize query planner statistics
    dbInstance.pragma('optimize');
  }
  
  return dbInstance;
}

export function closeDatabase(): void {
  if (dbInstance) {
    // Persist query planner statistics before closing
    dbInstance.pragma('optimize');
    dbInstance.close();
    dbInstance = null;
  }
}

function runMigrations(db: Database.Database) {
  // Disable foreign keys during migrations
  db.pragma('foreign_keys = OFF');
  
  try {
    createBaseTables(db);
    createUserTables(db);
    createIndexes(db);
    runDataMigrations(db);
  } finally {
    // Re-enable foreign keys
    db.pragma('foreign_keys = ON');
  }
}

function createBaseTables(db: Database.Database) {
  // Rules table
  db.exec(`
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
      webhook_ids TEXT,
      enabled BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Alerts table
  db.exec(`
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
}

function createUserTables(db: Database.Database) {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 20),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN DEFAULT 0,
      is_super_admin BOOLEAN DEFAULT 0,
      is_approved BOOLEAN DEFAULT 0,
      totp_enabled BOOLEAN DEFAULT 0,
      totp_secret_encrypted TEXT,
      recovery_codes_encrypted TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Webhooks table
  db.exec(`
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

  // Audit log table
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      event_data TEXT,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Admin actions table
  db.exec(`
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

  // Refresh tokens table
  db.exec(`
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
    )
  `);

  // Access token blacklist table
  db.exec(`
    CREATE TABLE IF NOT EXISTS access_token_blacklist (
      jti TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at DATETIME NOT NULL,
      reason TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

function createIndexes(db: Database.Database) {
  // Rules indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_rules_user_id ON rules (user_id);
    CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
    CREATE INDEX IF NOT EXISTS idx_rules_user_enabled ON rules (user_id, enabled);
  `);

  // Alerts indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_alerts_sale_id ON alerts (sale_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_sent_at ON alerts (sent_at);
    CREATE INDEX IF NOT EXISTS idx_alerts_rule_sent ON alerts (rule_id, sent_at DESC);
  `);

  // Users indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_approved ON users(is_approved);
    CREATE INDEX IF NOT EXISTS idx_users_admin_approved ON users(is_admin, is_approved);
  `);

  // Webhooks indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON user_webhooks(user_id);
    CREATE INDEX IF NOT EXISTS idx_webhooks_user_active ON user_webhooks(user_id, is_active);
  `);

  // Audit log indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_log_user_created ON audit_log(user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_user_event_date ON audit_log(user_id, event_type, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_event_created ON audit_log(event_type, created_at DESC);
  `);

  // Admin actions indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_admin_actions_admin ON admin_actions(admin_user_id);
    CREATE INDEX IF NOT EXISTS idx_admin_actions_target ON admin_actions(target_user_id);
    CREATE INDEX IF NOT EXISTS idx_admin_actions_created ON admin_actions(created_at);
    CREATE INDEX IF NOT EXISTS idx_admin_actions_admin_created ON admin_actions(admin_user_id, created_at DESC);
  `);

  // Refresh tokens indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry_revoked ON refresh_tokens(expires_at, revoked_at);
  `);

  // Access token blacklist indexes
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_token_blacklist_expiry ON access_token_blacklist(expires_at);
    CREATE INDEX IF NOT EXISTS idx_token_blacklist_user ON access_token_blacklist(user_id);
  `);
}

function runDataMigrations(db: Database.Database) {
  // Migration: Add is_admin column if it doesn't exist
  const hasIsAdmin = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_admin'
  `).get() as { count: number };

  if (hasIsAdmin.count === 0) {
    db.exec(`ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0`);
    migrationLogger.info('Migration: Added is_admin column to users table');
  }

  // Migration: Add is_super_admin column if it doesn't exist
  const hasIsSuperAdmin = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_super_admin'
  `).get() as { count: number };

  if (hasIsSuperAdmin.count === 0) {
    db.exec(`ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN DEFAULT 0`);
    migrationLogger.info('Migration: Added is_super_admin column to users table');
    
    // Make the first user a super admin if exists
    const firstUser = db.prepare('SELECT id FROM users ORDER BY id LIMIT 1').get() as { id: number } | undefined;
    if (firstUser) {
      db.prepare('UPDATE users SET is_super_admin = 1, is_admin = 1 WHERE id = ?').run(firstUser.id);
      migrationLogger.info(`Migration: Made first user (ID: ${firstUser.id}) a super admin`);
    }
  }

  // Migration: Add is_approved column if it doesn't exist
  const hasIsApproved = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='is_approved'
  `).get() as { count: number };

  if (hasIsApproved.count === 0) {
    db.exec(`ALTER TABLE users ADD COLUMN is_approved BOOLEAN DEFAULT 0`);
    migrationLogger.info('Migration: Added is_approved column to users table');
    
    // Approve all existing users
    db.prepare('UPDATE users SET is_approved = 1').run();
    migrationLogger.info('Migration: Approved all existing users');
  }

  // Migration: Add new filter columns to rules table if they don't exist
  const hasStattrakFilter = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('rules') WHERE name='stattrak_filter'
  `).get() as { count: number };

  if (hasStattrakFilter.count === 0) {
    db.exec(`ALTER TABLE rules ADD COLUMN stattrak_filter TEXT DEFAULT 'all'`);
    db.exec(`ALTER TABLE rules ADD COLUMN souvenir_filter TEXT DEFAULT 'all'`);
    db.exec(`ALTER TABLE rules ADD COLUMN allow_stickers BOOLEAN DEFAULT 1`);
    migrationLogger.info('Migration: Added filter columns to rules table');
  }

  // Migration: Add encrypted 2FA columns (skip plaintext columns)
  // First ensure totp_enabled exists
  const hasTotpEnabled = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_enabled'
  `).get() as { count: number };

  if (hasTotpEnabled.count === 0) {
    db.exec(`ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0`);
    migrationLogger.info('Migration: Added totp_enabled column to users table');
  }

  const hasEncryptedSecret = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_secret_encrypted'
  `).get() as { count: number };

  if (hasEncryptedSecret.count === 0) {
    db.exec(`ALTER TABLE users ADD COLUMN totp_secret_encrypted TEXT`);
    db.exec(`ALTER TABLE users ADD COLUMN recovery_codes_encrypted TEXT`);
    migrationLogger.info('Migration: Added encrypted 2FA columns to users table');
  }

  // Migration: Remove plaintext 2FA columns (security fix)
  const hasPlaintextSecret = db.prepare(`
    SELECT COUNT(*) as count FROM pragma_table_info('users') WHERE name='totp_secret'
  `).get() as { count: number };

  if (hasPlaintextSecret.count > 0) {
    // SQLite doesn't support DROP COLUMN before 3.35.0
    // We need to recreate the table without these columns
    db.exec(`
      -- Create new table without plaintext 2FA columns
      CREATE TABLE users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        is_super_admin BOOLEAN DEFAULT 0,
        is_approved BOOLEAN DEFAULT 0,
        totp_enabled BOOLEAN DEFAULT 0,
        totp_secret_encrypted TEXT,
        recovery_codes_encrypted TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      
      -- Copy data from old table
      INSERT INTO users_new (id, username, email, password_hash, is_admin, is_super_admin, is_approved, totp_enabled, totp_secret_encrypted, recovery_codes_encrypted, created_at, updated_at)
      SELECT id, username, email, password_hash, is_admin, is_super_admin, is_approved, totp_enabled, totp_secret_encrypted, recovery_codes_encrypted, created_at, updated_at
      FROM users;
      
      -- Drop old table
      DROP TABLE users;
      
      -- Rename new table
      ALTER TABLE users_new RENAME TO users;
    `);
    migrationLogger.info('Migration: Removed plaintext 2FA columns from users table (security fix)');
  }
}
