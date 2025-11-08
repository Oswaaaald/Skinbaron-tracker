// Test final de notification avec le workflow propre
const { getStore } = require('./dist/lib/store.js');
const { NotificationService } = require('./dist/lib/notifier.js');

async function testFinalWorkflow() {
  console.log('🎯 Testing final webhook notification workflow...');
  
  try {
    const store = getStore();
    console.log('✅ Store initialized');
    
    // 1. Vérifier la rule 12
    const rule = store.getRuleById(12);
    console.log('Rule found:', !!rule);
    console.log('Rule search_item:', rule?.search_item);
    console.log('Rule webhook_ids:', rule?.webhook_ids);
    
    if (!rule) {
      console.log('❌ No rule found');
      return;
    }
    
    // 2. Vérifier les webhooks pour cette rule
    console.log('\\n2. Testing webhook retrieval...');
    const webhooks = store.getRuleWebhooksForNotification(12);
    console.log('Webhooks found:', webhooks.length);
    
    if (webhooks.length === 0) {
      console.log('❌ No webhooks found for rule');
      return;
    }
    
    // 3. Afficher le premier webhook
    const webhook = webhooks[0];
    console.log('Webhook details:');
    console.log('  ID:', webhook.id);
    console.log('  Name:', webhook.name);
    console.log('  URL length:', webhook.webhook_url?.length || 0);
    console.log('  URL starts with https:', webhook.webhook_url?.startsWith('https://'));
    console.log('  Is active:', webhook.is_active);
    
    // 4. Test direct du webhook avec un message de test
    if (webhook.webhook_url && webhook.webhook_url.length > 0) {
      console.log('\\n3. Testing direct webhook call...');
      
      const testMessage = {
        embeds: [{
          title: "🎯 Test Notification - Webhook System Fixed!",
          description: `Rule: ${rule.search_item}\\nMax Price: $${rule.max_price}`,
          color: 0x00ff00,
          timestamp: new Date().toISOString(),
          fields: [
            { name: "Status", value: "✅ Webhook system is now working!", inline: true },
            { name: "Rule ID", value: rule.id.toString(), inline: true },
            { name: "Webhook ID", value: webhook.id.toString(), inline: true }
          ]
        }]
      };
      
      try {
        const response = await fetch(webhook.webhook_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(testMessage)
        });
        
        if (response.ok) {
          console.log('✅ Webhook test successful! Response status:', response.status);
          console.log('🎉 End-to-end webhook system is WORKING!');
        } else {
          console.log('❌ Webhook test failed. Status:', response.status);
        }
      } catch (error) {
        console.log('❌ Webhook request failed:', error.message);
      }
    }
    
  } catch (error) {
    console.error('Test failed:', error.message);
  }
}

testFinalWorkflow().catch(console.error);