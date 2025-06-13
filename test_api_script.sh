#!/bin/bash

# test_api.sh - Script to test the CRUD API

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the CloudFront URL from Terraform output
CLOUDFRONT_URL=$(terraform output -raw cloudfront_url 2>/dev/null)
API_GATEWAY_URL=$(terraform output -raw api_gateway_url 2>/dev/null)

if [ -z "$CLOUDFRONT_URL" ] || [ -z "$API_GATEWAY_URL" ]; then
    echo -e "${RED}Error: Could not get URLs from Terraform output${NC}"
    echo "Make sure you've run 'terraform apply' successfully"
    exit 1
fi

echo -e "${BLUE}=== CRUD API Testing Script ===${NC}"
echo -e "${YELLOW}CloudFront URL: $CLOUDFRONT_URL${NC}"
echo -e "${YELLOW}API Gateway URL: $API_GATEWAY_URL${NC}"
echo ""

# Function to make requests and show results
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local description=$4
    
    echo -e "${BLUE}$description${NC}"
    echo -e "${YELLOW}$method $url${NC}"
    
    if [ -n "$data" ]; then
        echo -e "${YELLOW}Data: $data${NC}"
        response=$(curl -s -w "HTTP_STATUS:%{http_code}" -X "$method" "$url" \
            -H "Content-Type: application/json" \
            -d "$data")
    else
        response=$(curl -s -w "HTTP_STATUS:%{http_code}" -X "$method" "$url")
    fi
    
    # Extract HTTP status and body
    http_status=$(echo "$response" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')
    
    if [ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ]; then
        echo -e "${GREEN}✓ Success (HTTP $http_status)${NC}"
    else
        echo -e "${RED}✗ Failed (HTTP $http_status)${NC}"
    fi
    
    echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
    echo ""
    echo "----------------------------------------"
    echo ""
    
    # Return the response for further processing
    echo "$body"
}

# Wait for CloudFront to be ready (optional)
echo -e "${YELLOW}Testing API endpoints...${NC}"
echo ""

# Test 1: Get all items (should be empty initially)
echo -e "${BLUE}TEST 1: Get all items (empty list)${NC}"
make_request "GET" "$CLOUDFRONT_URL/items" "" "Getting all items"

# Test 2: Create a new item
echo -e "${BLUE}TEST 2: Create a new item${NC}"
create_response=$(make_request "POST" "$CLOUDFRONT_URL/items" \
    '{"name": "Test Item 1", "description": "This is a test item"}' \
    "Creating a new item")

# Extract item ID from create response
ITEM_ID=$(echo "$create_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('id', ''))
except:
    pass
" 2>/dev/null)

if [ -n "$ITEM_ID" ]; then
    echo -e "${GREEN}Created item with ID: $ITEM_ID${NC}"
    echo ""
else
    echo -e "${RED}Failed to extract item ID${NC}"
    exit 1
fi

# Test 3: Create another item
echo -e "${BLUE}TEST 3: Create another item${NC}"
create_response2=$(make_request "POST" "$CLOUDFRONT_URL/items" \
    '{"name": "Test Item 2", "description": "Another test item"}' \
    "Creating another item")

ITEM_ID2=$(echo "$create_response2" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('id', ''))
except:
    pass
" 2>/dev/null)

# Test 4: Get all items (should show 2 items)
echo -e "${BLUE}TEST 4: Get all items (should show 2 items)${NC}"
make_request "GET" "$CLOUDFRONT_URL/items" "" "Getting all items"

# Test 5: Get specific item
echo -e "${BLUE}TEST 5: Get specific item${NC}"
make_request "GET" "$CLOUDFRONT_URL/items/$ITEM_ID" "" "Getting item by ID"

# Test 6: Update item
echo -e "${BLUE}TEST 6: Update item${NC}"
make_request "PUT" "$CLOUDFRONT_URL/items/$ITEM_ID" \
    '{"name": "Updated Test Item", "description": "This item has been updated"}' \
    "Updating item"

# Test 7: Get updated item
echo -e "${BLUE}TEST 7: Get updated item${NC}"
make_request "GET" "$CLOUDFRONT_URL/items/$ITEM_ID" "" "Getting updated item"

# Test 8: Delete item
echo -e "${BLUE}TEST 8: Delete item${NC}"
make_request "DELETE" "$CLOUDFRONT_URL/items/$ITEM_ID" "" "Deleting item"

# Test 9: Try to get deleted item (should return 404)
echo -e "${BLUE}TEST 9: Try to get deleted item (should fail)${NC}"
make_request "GET" "$CLOUDFRONT_URL/items/$ITEM_ID" "" "Getting deleted item (should return 404)"

# Test 10: Get all items (should show 1 item remaining)
echo -e "${BLUE}TEST 10: Get remaining items${NC}"
make_request "GET" "$CLOUDFRONT_URL/items" "" "Getting remaining items"

# Test 11: Test error handling - invalid JSON
echo -e "${BLUE}TEST 11: Test error handling with invalid JSON${NC}"
make_request "POST" "$CLOUDFRONT_URL/items" \
    '{"name": "Invalid JSON"' \
    "Testing with invalid JSON"

# Test 12: Test via API Gateway directly
echo -e "${BLUE}TEST 12: Test via API Gateway directly${NC}"
make_request "GET" "$API_GATEWAY_URL/items" "" "Getting items via API Gateway"

echo -e "${GREEN}=== All tests completed! ===${NC}"
echo ""
echo -e "${YELLOW}Manual testing commands:${NC}"
echo ""
echo "# Create item:"
echo "curl -X POST \"$CLOUDFRONT_URL/items\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"name\": \"My Item\", \"description\": \"My description\"}'"
echo ""
echo "# Get all items:"
echo "curl -X GET \"$CLOUDFRONT_URL/items\""
echo ""
echo "# Get specific item (replace ITEM_ID):"
echo "curl -X GET \"$CLOUDFRONT_URL/items/ITEM_ID\""
echo ""
echo "# Update item (replace ITEM_ID):"
echo "curl -X PUT \"$CLOUDFRONT_URL/items/ITEM_ID\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"name\": \"Updated\", \"description\": \"Updated description\"}'"
echo ""
echo "# Delete item (replace ITEM_ID):"
echo "curl -X DELETE \"$CLOUDFRONT_URL/items/ITEM_ID\""
