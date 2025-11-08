const CryptoJS = require('crypto-js');
const Database = require('better-sqlite3');

async function migrateWebhooks() {
  console.log('🔄 Migrating webhooks to fixed JWT_SECRET...');
  
  const db = new Database('data/alerts.db');
  
  // The current/old JWT_SECRET that was loaded from config during this session
  const { appConfig } = require('./dist/lib/config.js');
  const oldKey = appConfig.JWT_SECRET;
  
  // The new fixed JWT_SECRET that will be in docker-compose.yml
  const newKey = 'skinbaron-alerts-jwt-secret-2024-production-key-do-not-change';
  
  console.log('Old key length:', oldKey?.length || 0);
  console.log('New key length:', newKey.length);
  
  try {
    // Get all webhooks
    const webhooks = db.prepare('SELECT id, webhook_url_encrypted FROM user_webhooks').all();
    console.log('Found webhooks:', webhooks.length);
    
    let migratedCount = 0;
    
    for (const webhook of webhooks) {
      try {
        // Decrypt with old key
        const decrypted = CryptoJS.AES.decrypt(webhook.webhook_url_encrypted, oldKey).toString(CryptoJS.enc.Utf8);
        
        if (!decrypted || decrypted.length === 0) {
          console.warn('Failed to decrypt webhook', webhook.id);
          continue;
        }
        
        // Re-encrypt with new key
        const newEncrypted = CryptoJS.AES.encrypt(decrypted, newKey).toString();
        
        // Update in database
        const updateStmt = db.prepare('UPDATE user_webhooks SET webhook_url_encrypted = ? WHERE id = ?');
        updateStmt.run(newEncrypted, webhook.id);
        
        // Verify
        const testDecrypt = CryptoJS.AES.decrypt(newEncrypted, newKey).toString(CryptoJS.enc.Utf8);
        if (testDecrypt === decrypted) {
          console.log('✅ Migrated webhook', webhook.id);
          migratedCount++;
        } else {
          console.error('❌ Verification failed for webhook', webhook.id);
        }
        
      } catch (error) {
        console.error('Error migrating webhook', webhook.id, ':', error.message);
      }
    }
    
    console.log('Migration complete:', migratedCount, 'webhooks migrated');
    
  } catch (error) {
    console.error('Migration failed:', error.message);
  } finally {
    db.close();
  }
}

migrateWebhooks().catch(console.error);