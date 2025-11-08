const CryptoJS = require('crypto-js');
const { appConfig } = require('./dist/lib/config.js');

async function testEncryptionConsistency() {
  console.log('🔐 Testing encryption consistency...');
  
  const testUrl = 'https://discord.com/api/webhooks/1232724881716543578/KITr5fyiBxNoeuvC_lMfOVuZ4Y9PaC0YqKeJqTLz0Z7mXVaD72PdKh4EBYs5sjXPfd0k';
  const secretKey = appConfig.JWT_SECRET;
  
  console.log('Secret key length:', secretKey?.length || 0);
  
  try {
    // Test 1: Direct encryption/decryption
    console.log('\\n1. Testing direct encryption/decryption...');
    const encrypted = CryptoJS.AES.encrypt(testUrl, secretKey).toString();
    console.log('Encrypted length:', encrypted.length);
    
    const decrypted = CryptoJS.AES.decrypt(encrypted, secretKey).toString(CryptoJS.enc.Utf8);
    console.log('Decrypted length:', decrypted.length);
    console.log('URLs match:', decrypted === testUrl);
    
    // Test 2: Check what's in database
    console.log('\\n2. Checking database...');
    const Database = require('better-sqlite3');
    const db = new Database('data/alerts.db');
    
    const webhook = db.prepare('SELECT id, webhook_url_encrypted FROM user_webhooks WHERE id = 10').get();
    console.log('Webhook in DB:', !!webhook);
    
    if (webhook) {
      console.log('DB encrypted length:', webhook.webhook_url_encrypted.length);
      
      // Try to decrypt what's in DB
      try {
        const dbDecrypted = CryptoJS.AES.decrypt(webhook.webhook_url_encrypted, secretKey).toString(CryptoJS.enc.Utf8);
        console.log('DB decrypted length:', dbDecrypted.length);
        console.log('DB decryption success:', dbDecrypted.length > 0 && dbDecrypted.startsWith('https://'));
        
        if (dbDecrypted.length > 0) {
          console.log('DB decrypted URL preview:', dbDecrypted.substring(0, 50) + '...');
        }
      } catch (error) {
        console.error('DB decryption failed:', error.message);
      }
    }
    
    db.close();
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testEncryptionConsistency().catch(console.error);