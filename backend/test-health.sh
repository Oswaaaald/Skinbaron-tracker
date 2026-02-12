#!/bin/bash

# Script pour tester les health checks en conditions réelles
# Usage: ./test-health.sh [token]

TOKEN="${1:-YOUR_ADMIN_TOKEN_HERE}"
BASE_URL="http://localhost:8080"

echo "=== Testing System Health Checks ==="
echo ""

# Function to make request and show result
test_endpoint() {
    local name="$1"
    local endpoint="$2"
    
    echo ">>> Testing: $name"
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL$endpoint")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    echo "Status Code: $http_code"
    echo "Response:"
    echo "$body" | jq '.' 2>/dev/null || echo "$body"
    echo ""
}

# Test the system status endpoint
test_endpoint "System Status" "/api/system/status"

echo "=== Health Check Details ==="
echo ""
echo "Database Test:"
echo "- Performs: SELECT 1 query"
echo "- Healthy if: Returns 1"
echo "- To test failure: chmod 000 skinbaron.db"
echo ""
echo "SkinBaron API Test:"
echo "- Performs: Real API search for 'AK-47'"
echo "- Detects: 401/403 = Invalid API key, other errors = API down/network issue"
echo "- Healthy if: API responds with 200"
echo "- To test failure: Set SB_API_KEY=invalid_key in .env"
echo ""
echo "Scheduler Test:"
echo "- Checks: isRunning flag and error count"
echo "- Healthy if: Running with no errors, or stopped with no errors"
echo "- Shows: lastError if any errors occurred"
echo ""

echo "=== Manual Tests You Can Do ==="
echo ""
echo "1. Database offline:"
echo "   chmod 000 skinbaron.db"
echo "   Restart server → Check status → Should show 'unhealthy'"
echo "   chmod 644 skinbaron.db (restore)"
echo ""
echo "2. Invalid SkinBaron API Key:"
echo "   Edit .env: SB_API_KEY=invalid_key_12345"
echo "   Restart server → Check status → Should show 'unhealthy'"
echo "   Error message will say: 'Invalid or missing API key (401)'"
echo "   Restore correct API key in .env"
echo ""
echo "3. SkinBaron API Down:"
echo "   Disconnect network OR block skinbaron.de in /etc/hosts"
echo "   Check status → Should show 'unhealthy'"
echo ""
echo "4. Scheduler errors:"
echo "   Already tracked automatically in errorCount/lastError"
echo "   Any scheduler failures will be logged and reported"
echo ""
