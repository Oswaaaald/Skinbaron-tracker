import { FastifyInstance } from 'fastify';
import { getSkinBaronClient } from '../lib/sbclient.js';

export default async function testRoutes(fastify: FastifyInstance) {
  // Test SkinBaron API with real key
  fastify.post('/api/test/skinbaron', async (request, reply) => {
    try {
      const { apiKey, testSearch = 'AK-47' } = request.body as { 
        apiKey?: string; 
        testSearch?: string; 
      };

      if (!apiKey) {
        return reply.status(400).send({
          success: false,
          message: 'API key is required for testing'
        });
      }

      // Temporarily create a client with the test key
      const originalKey = process.env.SB_API_KEY;
      process.env.SB_API_KEY = apiKey;

      const client = getSkinBaronClient();
      
      // Test multiple endpoints
      const tests: {
        connection: boolean | null;
        search: any;
        bestDeals: any;
        newest: any;
      } = {
        connection: null,
        search: null,
        bestDeals: null,
        newest: null
      };

      try {
        // Test 1: Basic search
        console.log('🔍 Testing search...');
        tests.search = await client.search({
          search_item: testSearch,
          limit: 3
        });

        // Test 2: Best deals
        console.log('🔍 Testing best deals...');
        tests.bestDeals = await client.getBestDeals({ limit: 3 });

        // Test 3: Newest items
        console.log('🔍 Testing newest items...');
        tests.newest = await client.getNewestItems({ limit: 3 });

        // Test 4: Connection test
        console.log('🔍 Testing connection...');
        tests.connection = await client.testConnection();

        return reply.send({
          success: true,
          message: 'SkinBaron API tests completed',
          results: {
            connectionWorking: tests.connection,
            searchResults: tests.search?.items?.length || 0,
            bestDealsResults: tests.bestDeals?.items?.length || 0,
            newestResults: tests.newest?.items?.length || 0,
            sampleItem: tests.search?.items?.[0] ? {
              name: tests.search.items[0].itemName,
              price: tests.search.items[0].price,
              saleId: tests.search.items[0].saleId,
              url: client.getSkinUrl(tests.search.items[0].saleId)
            } : null
          },
          detailedResults: {
            search: tests.search,
            bestDeals: tests.bestDeals,
            newest: tests.newest
          }
        });

      } finally {
        // Restore original key
        process.env.SB_API_KEY = originalKey;
      }

    } catch (error) {
      console.error('❌ SkinBaron test error:', error);
      return reply.status(500).send({
        success: false,
        message: 'SkinBaron API test failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Test webhook notification
  fastify.post('/api/test/webhook', async (request, reply) => {
    try {
      const { webhookUrl, testItem } = request.body as {
        webhookUrl: string;
        testItem?: any;
      };

      if (!webhookUrl) {
        return reply.status(400).send({
          success: false,
          message: 'Webhook URL is required'
        });
      }

      // Import the notifier
      const { getNotificationService } = await import('../lib/notifier.js');
      const notifier = getNotificationService();

      // Create a test item
      const mockItem = testItem || {
        saleId: 'test-123',
        itemName: 'AK-47 | Redline (Field-Tested)',
        price: 25.50,
        wearValue: 0.25,
        statTrak: false,
        souvenir: false,
        currency: 'EUR',
        sellerName: 'TestSeller'
      };

      const mockRule = {
        user_id: 'test-user',
        name: 'Test Rule',
        search_item: 'AK-47',
        max_price: 30,
        discord_webhook: webhookUrl,
        enabled: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      // Send test notification
      await notifier.sendNotification(webhookUrl, {
        item: mockItem,
        skinUrl: 'https://skinbaron.de/listing/test-123',
        alertType: 'match',
        rule: mockRule
      });

      return reply.send({
        success: true,
        message: 'Test webhook sent successfully',
        testData: {
          item: mockItem,
          rule: mockRule
        }
      });

    } catch (error) {
      console.error('❌ Webhook test error:', error);
      return reply.status(500).send({
        success: false,
        message: 'Webhook test failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Test full workflow (API + Webhook)
  fastify.post('/api/test/workflow', async (request, reply) => {
    try {
      const { 
        apiKey, 
        webhookUrl, 
        searchItem = 'AK-47',
        maxPrice = 100 
      } = request.body as {
        apiKey: string;
        webhookUrl: string;
        searchItem?: string;
        maxPrice?: number;
      };

      if (!apiKey || !webhookUrl) {
        return reply.status(400).send({
          success: false,
          message: 'API key and webhook URL are required'
        });
      }

      // Step 1: Test SkinBaron API
      const originalKey = process.env.SB_API_KEY;
      process.env.SB_API_KEY = apiKey;

      const client = getSkinBaronClient();
      const searchResult = await client.search({
        search_item: searchItem,
        max: maxPrice,
        limit: 5
      });

      process.env.SB_API_KEY = originalKey;

      if (!searchResult.success || !searchResult.items?.length) {
        return reply.send({
          success: false,
          message: 'No items found or API search failed',
          searchResult
        });
      }

      // Step 2: Test webhook with real item
      const { getNotificationService } = await import('../lib/notifier.js');
      const notifier = getNotificationService();

      const testItem = searchResult.items[0];
      if (!testItem) {
        return reply.send({
          success: false,
          message: 'No test item found'
        });
      }

      const mockRule = {
        user_id: 'workflow-test',
        name: `Test: ${searchItem}`,
        search_item: searchItem,
        max_price: maxPrice,
        discord_webhook: webhookUrl,
        enabled: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      await notifier.sendNotification(webhookUrl, {
        item: testItem, 
        skinUrl: client.getSkinUrl(testItem.saleId),
        alertType: 'match',
        rule: mockRule
      });

      return reply.send({
        success: true,
        message: 'Full workflow test completed successfully',
        results: {
          apiWorking: true,
          itemsFound: searchResult.items.length,
          webhookSent: true,
          testItem: {
            name: testItem.itemName,
            price: testItem.price,
            saleId: testItem.saleId,
            url: client.getSkinUrl(testItem.saleId)
          }
        }
      });

    } catch (error) {
      console.error('❌ Workflow test error:', error);
      return reply.status(500).send({
        success: false,
        message: 'Workflow test failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });
}