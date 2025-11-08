import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

export class DatabaseMigrations {
  private db: Database.Database;

  constructor(dbPath: string) {
    // Create directory if it doesn't exist
    const dbDir = dirname(dbPath);
    if (!existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }

    // Initialize database
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    
    // Initialize migrations tracking
    this.initMigrationsTable();
  }

  private initMigrationsTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        description TEXT NOT NULL,
        applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  private isMigrationApplied(version: number): boolean {
    const row = this.db.prepare('SELECT 1 FROM schema_migrations WHERE version = ?').get(version);
    return !!row;
  }

  private recordMigration(version: number, description: string) {
    const stmt = this.db.prepare('INSERT INTO schema_migrations (version, description) VALUES (?, ?)');
    stmt.run(version, description);
  }

  /**
   * Run all migrations to create multi-user system
   */
  runMigrations() {
    console.log('🔄 Running database migrations...');
    
    // Disable foreign keys during migration
    this.db.pragma('foreign_keys = OFF');
    
    try {
      // Migration 1: Create users table
      this.runMigration(1, 'Create users table', () => {
        this.createUsersTable();
      });

      // Migration 2: Create user_webhooks table
      this.runMigration(2, 'Create user_webhooks table', () => {
        this.createUserWebhooksTable();
      });

      // Migration 3: Update rules table for multi-user support
      this.runMigration(3, 'Update rules table for multi-user support', () => {
        this.updateRulesTable();
      });

      // Migration 4: Update alerts table for multi-user support  
      this.runMigration(4, 'Update alerts table for multi-user support', () => {
        this.updateAlertsTable();
      });

      // Migration 5: Create user sessions table
      this.runMigration(5, 'Create user sessions table', () => {
        this.createUserSessionsTable();
      });

      // Migration 6: Create database indexes
      this.runMigration(6, 'Create database indexes', () => {
        this.createIndexes();
      });
      
    } catch (error) {
      console.error('❌ Migration failed:', error);
      throw error;
    } finally {
      // Re-enable foreign keys
      this.db.pragma('foreign_keys = ON');
    }
    
    console.log('✅ Database migrations completed');
  }

  private runMigration(version: number, description: string, migrationFn: () => void): void {
    if (this.isMigrationApplied(version)) {
      console.log(`⏭️ Migration ${version}: ${description} - already applied`);
      return;
    }

    console.log(`📝 Migration ${version}: ${description}...`);
    migrationFn();
    this.recordMigration(version, description);
    console.log(`✅ Migration ${version} completed`);
  }

  /**
   * Create users table
   */
  private createUsersTable() {
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
    console.log('📝 Users table created');
  }

  /**
   * Create user webhooks table
   */
  private createUserWebhooksTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_webhooks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL CHECK(length(name) >= 1 AND length(name) <= 50),
        webhook_type TEXT NOT NULL DEFAULT 'discord' CHECK(webhook_type IN ('discord', 'slack', 'teams', 'webhook')),
        webhook_url_encrypted TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, name)
      )
    `);
    console.log('🔗 User webhooks table created');
  }

  /**
   * Update existing rules table for multi-user support
   */
  private updateRulesTable() {
    // Check if rules table exists
    const tableExists = this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='rules'
    `).get();

    if (!tableExists) {
      // Create new rules table if it doesn't exist
      this.db.exec(`
        CREATE TABLE rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          webhook_ids TEXT,
          search_item TEXT NOT NULL,
          min_price REAL CHECK(min_price >= 0),
          max_price REAL CHECK(max_price >= 0),
          min_wear REAL CHECK(min_wear >= 0 AND min_wear <= 1),
          max_wear REAL CHECK(max_wear >= 0 AND max_wear <= 1),
          stattrak BOOLEAN DEFAULT 0,
          souvenir BOOLEAN DEFAULT 0,
          enabled BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
          CHECK(min_price IS NULL OR max_price IS NULL OR min_price <= max_price),
          CHECK(min_wear IS NULL OR max_wear IS NULL OR min_wear <= max_wear)
        )
      `);
      console.log('📋 Rules table created');
      return;
    }

    // Check if user_id column exists
    const userIdExists = this.db.prepare(`
      SELECT sql FROM sqlite_master 
      WHERE type='table' AND name='rules' AND sql LIKE '%user_id%'
    `).get();

    if (!userIdExists) {
      console.log('🔄 Adding user_id column to rules table...');
      
      // Create backup
      this.db.exec(`
        CREATE TABLE rules_backup AS SELECT * FROM rules
      `);

      // Create new table with user_id
      this.db.exec(`
        CREATE TABLE rules_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL DEFAULT 1,
          webhook_ids TEXT,
          search_item TEXT NOT NULL,
          min_price REAL CHECK(min_price >= 0),
          max_price REAL CHECK(max_price >= 0),
          min_wear REAL CHECK(min_wear >= 0 AND min_wear <= 1),
          max_wear REAL CHECK(max_wear >= 0 AND max_wear <= 1),
          stattrak BOOLEAN DEFAULT 0,
          souvenir BOOLEAN DEFAULT 0,
          enabled BOOLEAN DEFAULT 1,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
          CHECK(min_price IS NULL OR max_price IS NULL OR min_price <= max_price),
          CHECK(min_wear IS NULL OR max_wear IS NULL or min_wear <= max_wear)
        )
      `);

      // Copy data from old table
      this.db.exec(`
        INSERT INTO rules_new (id, search_item, min_price, max_price, min_wear, max_wear, stattrak, souvenir, enabled, created_at, updated_at)
        SELECT id, search_item, min_price, max_price, min_wear, max_wear, stattrak, souvenir, enabled, 
               COALESCE(created_at, CURRENT_TIMESTAMP), COALESCE(updated_at, CURRENT_TIMESTAMP)
        FROM rules
      `);

      // Replace old table
      this.db.exec(`DROP TABLE rules`);
      this.db.exec(`ALTER TABLE rules_new RENAME TO rules`);
      
      console.log('✅ Rules table updated with user_id column');
    }

    // Check if webhook_ids column exists
    const webhookIdsExists = this.db.prepare(`
      SELECT sql FROM sqlite_master 
      WHERE type='table' AND name='rules' AND sql LIKE '%webhook_ids%'
    `).get();

    if (!webhookIdsExists) {
      console.log('🔄 Adding webhook_ids column to rules table...');
      this.db.exec(`ALTER TABLE rules ADD COLUMN webhook_ids TEXT`);
      console.log('✅ webhook_ids column added to rules table');
    }
  }

  /**
   * Update existing alerts table for multi-user support
   */
  private updateAlertsTable() {
    // Check if alerts table exists
    const tableExists = this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='alerts'
    `).get();

    if (!tableExists) {
      // Create new alerts table if it doesn't exist
      this.db.exec(`
        CREATE TABLE alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          sale_id TEXT NOT NULL,
          item_name TEXT NOT NULL,
          price REAL NOT NULL CHECK(price >= 0),
          wear_value REAL CHECK(wear_value >= 0 AND wear_value <= 1),
          stattrak BOOLEAN DEFAULT 0,
          souvenir BOOLEAN DEFAULT 0,
          skin_url TEXT NOT NULL,
          alert_type TEXT CHECK(alert_type IN ('match', 'best_deal', 'new_item')) DEFAULT 'match',
          sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
          UNIQUE(user_id, sale_id)
        )
      `);
      console.log('🚨 Alerts table created');
      return;
    }

    // Check if user_id column exists
    const userIdExists = this.db.prepare(`
      SELECT sql FROM sqlite_master 
      WHERE type='table' AND name='alerts' AND sql LIKE '%user_id%'
    `).get();

    if (!userIdExists) {
      console.log('🔄 Adding user_id column to alerts table...');
      
      // Create backup
      this.db.exec(`
        CREATE TABLE alerts_backup AS SELECT * FROM alerts
      `);

      // Create new table with user_id
      this.db.exec(`
        CREATE TABLE alerts_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          rule_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL DEFAULT 1,
          sale_id TEXT NOT NULL,
          item_name TEXT NOT NULL,
          price REAL NOT NULL CHECK(price >= 0),
          wear_value REAL CHECK(wear_value >= 0 AND wear_value <= 1),
          stattrak BOOLEAN DEFAULT 0,
          souvenir BOOLEAN DEFAULT 0,
          skin_url TEXT NOT NULL,
          alert_type TEXT CHECK(alert_type IN ('match', 'best_deal', 'new_item')) DEFAULT 'match',
          sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
          FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
          UNIQUE(user_id, sale_id)
        )
      `);

      // Copy data from old table
      this.db.exec(`
        INSERT INTO alerts_new (id, rule_id, sale_id, item_name, price, wear_value, stattrak, souvenir, skin_url, alert_type, sent_at)
        SELECT id, rule_id, sale_id, item_name, price, wear_value, stattrak, souvenir, skin_url, 
               COALESCE(alert_type, 'match'), COALESCE(sent_at, CURRENT_TIMESTAMP)
        FROM alerts
      `);

      // Replace old table
      this.db.exec(`DROP TABLE alerts`);
      this.db.exec(`ALTER TABLE alerts_new RENAME TO alerts`);
      
      console.log('✅ Alerts table updated with user_id column');
    }
  }

  /**
   * Create user sessions table for auth
   */
  private createUserSessionsTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      )
    `);
    console.log('🔐 User sessions table created');
  }

  /**
   * Create indexes for performance
   */
  private createIndexes() {
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_rules_user_id ON rules(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)',
      'CREATE INDEX IF NOT EXISTS idx_alerts_sale_id ON alerts(sale_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)',
      'CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON user_webhooks(user_id)',
    ];

    indexes.forEach(indexSql => {
      this.db.exec(indexSql);
    });
    
    console.log('📊 Database indexes created');
  }

  /**
   * Create a test admin user for initial setup
   */
  createTestUser(username: string, email: string, passwordHash: string): number {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO users (username, email, password_hash)
      VALUES (?, ?, ?)
    `);
    
    const result = stmt.run(username, email, passwordHash);
    return result.lastInsertRowid as number;
  }

  close() {
    this.db.close();
  }
}