const CryptoJS = require('crypto-js');
const { appConfig } = require('./dist/lib/config.js');
const Database = require('better-sqlite3');

async function fixWebhookEncryption() {
  console.log('🔧 Fixing webhook encryption...');
  
  const testUrl = 'https://discord.com/api/webhooks/1232724881716543578/KITr5fyiBxNoeuvC_lMfOVuZ4Y9PaC0YqKeJqTLz0Z7mXVaD72PdKh4EBYs5sjXPfd0k';
  const secretKey = appConfig.JWT_SECRET;
  
  const db = new Database('data/alerts.db');
  
  try {
    // Get current webhook
    const webhook = db.prepare('SELECT * FROM user_webhooks WHERE id = 10').get();
    console.log('Current webhook:', {
      id: webhook?.id,
      name: webhook?.name,
      encrypted_length: webhook?.webhook_url_encrypted?.length
    });
    
    // Re-encrypt with current key
    const newEncrypted = CryptoJS.AES.encrypt(testUrl, secretKey).toString();
    console.log('New encrypted length:', newEncrypted.length);
    
    // Test decryption
    const decrypted = CryptoJS.AES.decrypt(newEncrypted, secretKey).toString(CryptoJS.enc.Utf8);
    console.log('Test decryption works:', decrypted === testUrl);
    
    // Update in database
    const updateStmt = db.prepare('UPDATE user_webhooks SET webhook_url_encrypted = ? WHERE id = 10');
    const result = updateStmt.run(newEncrypted);
    console.log('Update result:', result.changes);
    
    // Verify
    const updated = db.prepare('SELECT webhook_url_encrypted FROM user_webhooks WHERE id = 10').get();
    const verifyDecrypt = CryptoJS.AES.decrypt(updated.webhook_url_encrypted, secretKey).toString(CryptoJS.enc.Utf8);
    console.log('Verification: decryption works =', verifyDecrypt === testUrl);
    
  } catch (error) {
    console.error('Fix failed:', error.message);
  } finally {
    db.close();
  }
}

fixWebhookEncryption().catch(console.error);