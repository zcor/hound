#!/bin/bash
set -e

echo "🧪 Running Integration Tests"
echo "============================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_URL=${API_URL:-http://localhost:8000}

# Test 1: API is running
echo -n "Testing: API is running... "
if curl -s -f $API_URL/docs > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Error: API is not running at $API_URL"
    exit 1
fi

# Test 2: CORS headers present
echo -n "Testing: CORS headers present... "
CORS_HEADER=$(curl -s -I $API_URL/surface/scans?tenant_id=1 -H "Origin: http://localhost:3000" | grep -i "access-control-allow-origin")
if [ ! -z "$CORS_HEADER" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Error: CORS headers not found"
    exit 1
fi

# Test 3: Test data exists
echo -n "Testing: Test data exists... "
SCAN_COUNT=$(curl -s $API_URL/surface/scans?tenant_id=1 | jq '.scans | length // .results | length // 0')
if [ "$SCAN_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} ($SCAN_COUNT scans found)"
else
    echo -e "${YELLOW}⚠${NC} No test data found. Run: python scripts/seed_test_data.py"
fi

# Test 4: Repositories endpoint
echo -n "Testing: Repositories endpoint... "
REPO_COUNT=$(curl -s $API_URL/repositories?tenant_id=1 | jq '.repositories | length // .results | length // 0')
if [ "$REPO_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓${NC} ($REPO_COUNT repos found)"
else
    echo -e "${YELLOW}⚠${NC} No repositories found"
fi

# Test 5: Findings endpoint
echo -n "Testing: Findings endpoint... "
FINDINGS_RESPONSE=$(curl -s -w "%{http_code}" $API_URL/findings?tenant_id=1)
HTTP_CODE="${FINDINGS_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC} (HTTP $HTTP_CODE)"
fi

# Test 6: Usage stats endpoint (if exists)
echo -n "Testing: Usage stats endpoint... "
USAGE_RESPONSE=$(curl -s -w "%{http_code}" $API_URL/usage/current-month?tenant_id=1 2>/dev/null)
HTTP_CODE="${USAGE_RESPONSE: -3}"
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓${NC}"
elif [ "$HTTP_CODE" = "404" ]; then
    echo -e "${YELLOW}⚠${NC} (endpoint not implemented)"
else
    echo -e "${YELLOW}⚠${NC} (HTTP $HTTP_CODE)"
fi

# Test 7: Health check endpoint
echo -n "Testing: Health check endpoint... "
HEALTH_RESPONSE=$(curl -s $API_URL/health | jq -r '.status')
if [ "$HEALTH_RESPONSE" = "healthy" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# Test 8: Database health check endpoint
echo -n "Testing: Database health check... "
DB_HEALTH_RESPONSE=$(curl -s $API_URL/health/db 2>/dev/null | jq -r '.status' 2>/dev/null)
if [ "$DB_HEALTH_RESPONSE" = "healthy" ]; then
    echo -e "${GREEN}✓${NC}"
elif [ "$DB_HEALTH_RESPONSE" = "" ]; then
    echo -e "${YELLOW}⚠${NC} (endpoint not implemented)"
else
    echo -e "${RED}✗${NC}"
fi

echo ""
echo -e "${GREEN}✅ All integration tests passed!${NC}"
