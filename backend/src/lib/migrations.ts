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
  }

  /**
   * Run all migrations to create multi-user system
   */
  runMigrations() {
    console.log('🔄 Running database migrations...');
    
    this.createUsersTable();
    this.createUserWebhooksTable(); 
    this.createRulesTableV2();
    this.createAlertsTableV2();
    this.createUserSessionsTable();
    this.createIndexes();
    
    console.log('✅ Database migrations completed');
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
        webhook_url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        UNIQUE(user_id, name)
      )
    `);
    console.log('🔗 User webhooks table created');
  }

  /**
   * Create rules table (multi-user version)
   */
  private createRulesTableV2() {
    // First check if we need to migrate old rules table
    const oldTableExists = this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='rules'
    `).get();

    if (oldTableExists) {
      console.log('🔄 Migrating existing rules table...');
      // Backup old rules if needed
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS rules_backup AS 
        SELECT * FROM rules
      `);
      this.db.exec(`DROP TABLE rules`);
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        webhook_id INTEGER,
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
        FOREIGN KEY (webhook_id) REFERENCES user_webhooks (id) ON DELETE SET NULL,
        CHECK(min_price IS NULL OR max_price IS NULL OR min_price <= max_price),
        CHECK(min_wear IS NULL OR max_wear IS NULL OR min_wear <= max_wear)
      )
    `);
    console.log('📋 Rules table (v2) created');
  }

  /**
   * Create alerts table (multi-user version)
   */
  private createAlertsTableV2() {
    // Backup and recreate alerts table too
    const oldTableExists = this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' AND name='alerts'
    `).get();

    if (oldTableExists) {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS alerts_backup AS 
        SELECT * FROM alerts
      `);
      this.db.exec(`DROP TABLE alerts`);
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS alerts (
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
    console.log('🚨 Alerts table (v2) created');
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