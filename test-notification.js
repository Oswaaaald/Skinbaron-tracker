const { getStore } = require('./dist/lib/store.js');
const { getNotificationService } = require('./dist/lib/notifier.js');

async function testWebhookNotification() {
  console.log('🧪 Testing webhook notification system...');
  
  try {
    const store = getStore();
    const notifier = getNotificationService();
    
    console.log('1. Getting rule 10...');
    const rule = store.getRuleById(10);
    if (!rule) {
      console.error('❌ Rule 10 not found');
      return;
    }
    
    console.log('✅ Rule found:', rule.search_item);
    console.log('📋 Rule webhook_ids:', rule.webhook_ids);
    
    console.log('2. Getting webhooks for notification...');
    const webhooks = store.getRuleWebhooksForNotification(10);
    console.log('📡 Webhooks found:', webhooks.length);
    
    if (webhooks.length === 0) {
      console.error('❌ No webhooks found for rule');
      return;
    }
    
    for (let i = 0; i < webhooks.length; i++) {
      const webhook = webhooks[i];
      console.log(`📡 Webhook ${i + 1}:`);
      console.log('   - Name:', webhook.name);
      console.log('   - Type:', webhook.webhook_type);
      console.log('   - URL length:', webhook.webhook_url?.length || 0);
      console.log('   - URL starts with https:', webhook.webhook_url?.startsWith('https://') || false);
      
      if (webhook.webhook_url && webhook.webhook_url.length > 0) {
        console.log('3. Testing notification...');
        
        try {
          const testResult = await notifier.testWebhook(webhook.webhook_url);
          console.log('✅ Webhook test result:', testResult);
          
          // Send actual test message
          const message = {
            content: '🎯 **Test depuis le système SkinBaron Alerts**\\n\\n' +
                    '✅ Webhook sauvegardé: ' + webhook.name + '\\n' +
                    '🔒 Déchiffrement: SUCCESS\\n' +
                    '📡 Notification: FONCTIONNEL\\n' +
                    '🎮 Rule test: ' + rule.search_item
          };
          
          const sendResult = await notifier.sendNotification(webhook.webhook_url, message);
          console.log('📬 Message sent result:', sendResult);
          
        } catch (error) {
          console.error('❌ Notification failed:', error.message);
        }
      } else {
        console.error('❌ Webhook URL is empty - decryption failed');
      }
    }
    
  } catch (error) {
    console.error('💥 Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

testWebhookNotification().catch(console.error);