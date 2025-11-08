// Test avec clé directe
const Database = require('better-sqlite3');
const CryptoJS = require('crypto-js');

function testDirectDecryption() {
  console.log('🔑 Testing direct decryption...');
  
  const db = new Database('data/alerts.db');
  
  // Get the webhook from DB
  const webhook = db.prepare('SELECT * FROM user_webhooks WHERE id = 10').get();
  console.log('Webhook found:', !!webhook);
  
  if (!webhook) {
    console.log('No webhook found');
    return;
  }
  
  console.log('Encrypted length:', webhook.webhook_url_encrypted.length);
  
  // Get JWT_SECRET from environment (same way as config)
  const jwtSecret = process.env.JWT_SECRET;
  console.log('JWT_SECRET from env:', !!jwtSecret, 'length:', jwtSecret?.length);
  
  // Test decryption
  try {
    const bytes = CryptoJS.AES.decrypt(webhook.webhook_url_encrypted, jwtSecret);
    console.log('Bytes object created:', !!bytes);
    console.log('Bytes words length:', bytes.words?.length || 0);
    
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    console.log('Decrypted length:', decrypted.length);
    console.log('Decrypted preview:', decrypted.substring(0, 50));
    console.log('Is valid URL:', decrypted.startsWith('https://'));
    
  } catch (error) {
    console.error('Decryption error:', error.message);
  }
  
  db.close();
}

testDirectDecryption();