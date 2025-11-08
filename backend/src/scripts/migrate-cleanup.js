#!/usr/bin/env node

/**
 * Migration script to clean up obsolete database elements:
 * 1. Drop the discord_webhook column from rules table
 * 2. Drop the unused rule_webhooks table
 * 3. Remove associated indexes
 */

import Database from 'better-sqlite3';
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Database path (adjust if needed)
const dbPath = process.env.SQLITE_PATH || join(__dirname, '../../data/database.db');

console.log('🔄 Starting database cleanup migration...');
console.log(`Database path: ${dbPath}`);

if (!existsSync(dbPath)) {
  console.log('❌ Database file not found. Nothing to migrate.');
  process.exit(0);
}

const db = new Database(dbPath);
db.pragma('foreign_keys = OFF'); // Disable foreign keys for migration

try {
  console.log('📊 Checking current database structure...');
  
  // Check if discord_webhook column exists in rules table
  const rulesTableInfo = db.prepare("PRAGMA table_info(rules)").all();
  const hasDiscordWebhook = rulesTableInfo.some(col => col.name === 'discord_webhook');
  
  // Check if rule_webhooks table exists
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const hasRuleWebhooksTable = tables.some(table => table.name === 'rule_webhooks');
  
  if (!hasDiscordWebhook && !hasRuleWebhooksTable) {
    console.log('✅ Database is already clean. No migration needed.');
    db.close();
    process.exit(0);
  }
  
  console.log('🔧 Starting migration...');
  
  // Begin transaction
  db.exec('BEGIN TRANSACTION');
  
  if (hasDiscordWebhook) {
    console.log('🗑️  Removing discord_webhook column from rules table...');
    
    // Create new table without discord_webhook column
    db.exec(`
      CREATE TABLE rules_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        search_item TEXT NOT NULL,
        min_price REAL,
        max_price REAL,
        min_wear REAL CHECK (min_wear >= 0 AND min_wear <= 1),
        max_wear REAL CHECK (max_wear >= 0 AND max_wear <= 1),
        stattrak BOOLEAN DEFAULT 0,
        souvenir BOOLEAN DEFAULT 0,
        webhook_ids TEXT,
        enabled BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Copy data from old table (excluding discord_webhook)
    db.exec(`
      INSERT INTO rules_new (id, user_id, search_item, min_price, max_price, min_wear, max_wear, 
                           stattrak, souvenir, webhook_ids, enabled, created_at, updated_at)
      SELECT id, user_id, search_item, min_price, max_price, min_wear, max_wear, 
             stattrak, souvenir, webhook_ids, enabled, created_at, updated_at
      FROM rules
    `);
    
    // Drop old table and rename new one
    db.exec('DROP TABLE rules');
    db.exec('ALTER TABLE rules_new RENAME TO rules');
    
    console.log('✅ discord_webhook column removed');
  }
  
  if (hasRuleWebhooksTable) {
    console.log('🗑️  Dropping unused rule_webhooks table...');
    db.exec('DROP TABLE IF EXISTS rule_webhooks');
    console.log('✅ rule_webhooks table dropped');
  }
  
  // Recreate indexes (they were lost when we recreated the table)
  console.log('📝 Recreating indexes...');
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_rules_user_id ON rules (user_id);
    CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
  `);
  
  // Commit transaction
  db.exec('COMMIT');
  
  console.log('✅ Migration completed successfully!');
  
} catch (error) {
  console.error('❌ Migration failed:', error);
  db.exec('ROLLBACK');
  throw error;
} finally {
  db.pragma('foreign_keys = ON'); // Re-enable foreign keys
  db.close();
}

console.log('🎉 Database cleanup migration finished!');