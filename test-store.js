// Test direct du store
const { getStore } = require('./dist/lib/store.js');

async function testStore() {
  console.log('🧪 Testing store directly...');
  
  try {
    const store = getStore();
    console.log('✅ Store initialized');
    
    // Test getting rule
    const rule = store.getRuleById(10);
    console.log('Rule found:', !!rule);
    console.log('Rule webhook_ids:', rule?.webhook_ids);
    
    if (rule && rule.webhook_ids?.length) {
      console.log('Getting webhooks for notification...');
      const webhooks = store.getRuleWebhooksForNotification(10);
      console.log('Webhooks found:', webhooks.length);
      
      if (webhooks.length > 0) {
        console.log('First webhook URL length:', webhooks[0].webhook_url?.length || 0);
        console.log('First webhook URL starts with https:', webhooks[0].webhook_url?.startsWith('https://'));
      }
    }
    
  } catch (error) {
    console.error('Store test failed:', error.message);
  }
}

testStore().catch(console.error);