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
echo "- To break: Stop database or corrupt DB file"
echo ""
echo "SkinBaron API Test:"
echo "- Performs: Real API search for 'AK-47'"
echo "- Healthy if: API responds successfully"
echo "- To break: Wrong API key, network issues, or API down"
echo ""
echo "Scheduler Test:"
echo "- Checks: isRunning flag and error count"
echo "- Healthy if: Running with no errors, or stopped with no errors"
echo "- To break: Scheduler encounters errors during execution"
echo ""

echo "=== Manual Tests You Can Do ==="
echo ""
echo "1. Database offline:"
echo "   - chmod 000 skinbaron.db (make it unreadable)"
echo "   - Restart server"
echo "   - Check /api/system/status"
echo "   - chmod 644 skinbaron.db (restore)"
echo ""
echo "2. SkinBaron API offline:"
echo "   - Set invalid SB_API_KEY in .env"
echo "   - Restart server"
echo "   - Check /api/system/status"
echo "   - Restore correct API key"
echo ""
echo "3. Scheduler issues:"
echo "   - Already tracked in errorCount/lastError"
echo "   - Check logs for scheduler errors"
echo ""
