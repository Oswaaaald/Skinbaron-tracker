#!/usr/bin/env node

/**
 * Script de test pour l'API SkinBaron
 * Usage: node test-skinbaron-api.js [API_KEY]
 */

import { request } from 'undici';

// Configuration
const SKINBARON_CONFIG = {
  BASE_URL: 'https://skinbaron.de/api/v2',
  APP_ID: 1,
  ENDPOINTS: {
    SEARCH: '/search',
    BEST_DEALS: '/bestDeals',
    NEWEST_ITEMS: '/newestItems'
  }
};

// Test data
const TEST_SEARCHES = [
  { search_item: 'AK-47', limit: 5 },
  { search_item: 'AWP Asiimov', limit: 3 },
  { search_item: 'Knife', limit: 2, max: 100 }
];

class SkinBaronTester {
  constructor(apiKey) {
    this.apiKey = apiKey;
    console.log('🔍 SkinBaron API Tester');
    console.log(`📡 Base URL: ${SKINBARON_CONFIG.BASE_URL}`);
    console.log(`🔑 API Key: ${apiKey ? '✅ Provided' : '❌ Missing'}`);
    console.log('─'.repeat(60));
  }

  async makeRequest(endpoint, params = {}) {
    try {
      const baseParams = {
        appid: SKINBARON_CONFIG.APP_ID.toString(),
        ...this.sanitizeParams(params)
      };

      // Add API key if provided
      if (this.apiKey) {
        baseParams.apikey = this.apiKey;
      }

      const searchParams = new URLSearchParams(baseParams);
      const url = `${SKINBARON_CONFIG.BASE_URL}${endpoint}`;

      console.log(`🔍 Testing: ${endpoint}`);
      console.log(`📋 Params:`, Object.fromEntries(searchParams.entries()));

      const startTime = Date.now();
      
      const { statusCode, headers, body } = await request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'SkinBaron-Alerts-Test/1.0',
        },
        body: searchParams.toString(),
      });

      const responseTime = Date.now() - startTime;
      const rawData = await body.text();

      console.log(`📊 Status: ${statusCode} (${responseTime}ms)`);
      console.log(`📄 Headers:`, Object.fromEntries(Object.entries(headers)));

      let jsonData;
      try {
        jsonData = JSON.parse(rawData);
      } catch (parseError) {
        console.log(`❌ Parse Error: Invalid JSON`);
        console.log(`📄 Raw Response (first 500 chars):`);
        console.log(rawData.substring(0, 500));
        return { success: false, error: 'Invalid JSON', raw: rawData.substring(0, 500) };
      }

      if (statusCode === 200) {
        console.log(`✅ Success! Items: ${jsonData.items?.length || 0}`);
        if (jsonData.items && jsonData.items.length > 0) {
          console.log(`📦 Sample item:`, {
            name: jsonData.items[0].itemName,
            price: jsonData.items[0].price,
            saleId: jsonData.items[0].saleId
          });
        }
      } else {
        console.log(`❌ Error ${statusCode}:`, jsonData.message || 'Unknown error');
      }

      console.log('─'.repeat(40));
      return { success: statusCode === 200, data: jsonData, statusCode, responseTime };

    } catch (error) {
      console.log(`❌ Request failed:`, error.message);
      console.log('─'.repeat(40));
      return { success: false, error: error.message };
    }
  }

  sanitizeParams(params) {
    const sanitized = {};
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        if (typeof value === 'boolean') {
          sanitized[key] = value ? '1' : '0';
        } else {
          sanitized[key] = String(value);
        }
      }
    }
    return sanitized;
  }

  async runTests() {
    const results = {
      total: 0,
      success: 0,
      failed: 0,
      tests: []
    };

    console.log('🚀 Starting API tests...\n');

    // Test 1: Connection test with minimal params
    console.log('📍 Test 1: Basic Connection');
    const connectionTest = await this.makeRequest('/search', { search_item: 'AK-47', limit: 1 });
    results.total++;
    if (connectionTest.success) {
      results.success++;
      console.log('✅ Connection test PASSED\n');
    } else {
      results.failed++;
      console.log('❌ Connection test FAILED\n');
    }
    results.tests.push({ name: 'Connection Test', ...connectionTest });

    // Test 2: Search endpoint with various params
    for (let i = 0; i < TEST_SEARCHES.length; i++) {
      const searchParams = TEST_SEARCHES[i];
      console.log(`📍 Test ${i + 2}: Search - "${searchParams.search_item}"`);
      
      const searchTest = await this.makeRequest('/search', searchParams);
      results.total++;
      if (searchTest.success) {
        results.success++;
        console.log('✅ Search test PASSED\n');
      } else {
        results.failed++;
        console.log('❌ Search test FAILED\n');
      }
      results.tests.push({ name: `Search: ${searchParams.search_item}`, ...searchTest });
    }

    // Test 3: Best deals endpoint
    console.log('📍 Test 5: Best Deals');
    const bestDealsTest = await this.makeRequest('/bestDeals', { limit: 3 });
    results.total++;
    if (bestDealsTest.success) {
      results.success++;
      console.log('✅ Best deals test PASSED\n');
    } else {
      results.failed++;
      console.log('❌ Best deals test FAILED\n');
    }
    results.tests.push({ name: 'Best Deals', ...bestDealsTest });

    // Test 4: Newest items endpoint
    console.log('📍 Test 6: Newest Items');
    const newestTest = await this.makeRequest('/newestItems', { limit: 3 });
    results.total++;
    if (newestTest.success) {
      results.success++;
      console.log('✅ Newest items test PASSED\n');
    } else {
      results.failed++;
      console.log('❌ Newest items test FAILED\n');
    }
    results.tests.push({ name: 'Newest Items', ...newestTest });

    return results;
  }

  printSummary(results) {
    console.log('='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));
    console.log(`📊 Total tests: ${results.total}`);
    console.log(`✅ Passed: ${results.success}`);
    console.log(`❌ Failed: ${results.failed}`);
    console.log(`📈 Success rate: ${((results.success / results.total) * 100).toFixed(1)}%`);

    if (results.success === results.total) {
      console.log('\n🎉 ALL TESTS PASSED! Your API key works perfectly!');
      console.log('🚀 You can now enable SkinBaron monitoring in your app.');
    } else if (results.success > 0) {
      console.log('\n⚠️  PARTIAL SUCCESS - Some endpoints work');
      console.log('📝 Check the failed tests for specific issues.');
    } else {
      console.log('\n💥 ALL TESTS FAILED');
      console.log('🔍 Possible issues:');
      console.log('   • Invalid API key');
      console.log('   • API endpoint changes');
      console.log('   • Rate limiting');
      console.log('   • Network connectivity');
    }

    console.log('\n📋 DETAILED RESULTS:');
    results.tests.forEach((test, i) => {
      const status = test.success ? '✅' : '❌';
      console.log(`   ${status} ${test.name} (${test.responseTime || 'N/A'}ms)`);
      if (!test.success && test.error) {
        console.log(`      Error: ${test.error}`);
      }
    });

    console.log('\n🔗 Next steps:');
    if (results.success === results.total) {
      console.log('   1. Update your .env with the working API key');
      console.log('   2. Restart your Docker containers');
      console.log('   3. Enable the SkinBaron API in sbclient.ts');
    } else {
      console.log('   1. Verify your API key with SkinBaron support');
      console.log('   2. Check API documentation for changes');
      console.log('   3. Test with different parameters');
    }
  }
}

// Main execution
async function main() {
  const apiKey = process.argv[2] || process.env.SB_API_KEY;
  
  if (!apiKey) {
    console.log('❌ No API key provided!');
    console.log('Usage: node test-skinbaron-api.js YOUR_API_KEY');
    console.log('   or: SB_API_KEY=your_key node test-skinbaron-api.js');
    process.exit(1);
  }

  const tester = new SkinBaronTester(apiKey);
  
  try {
    const results = await tester.runTests();
    tester.printSummary(results);
    
    // Exit with appropriate code
    process.exit(results.success === results.total ? 0 : 1);
  } catch (error) {
    console.error('💥 Test runner failed:', error);
    process.exit(1);
  }
}

main().catch(console.error);