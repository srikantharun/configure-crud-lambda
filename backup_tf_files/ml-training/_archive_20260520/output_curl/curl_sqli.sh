#!/bin/bash
# WAF Bypass Test — SQLI (10 payloads)
# Run: bash curl_sqli.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[sqli] juiceshop-0049: admin' #"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0049" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "admin\' #"}'
echo ""

echo "[sqli] juiceshop-0053: %2527%2520OR%25201%253D1--"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0053" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1--"}'
echo ""

echo "[sqli] juiceshop-0056: %27--+"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0056" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%27--+"}'
echo ""

echo "[sqli] juiceshop-0071: admin%27--+"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0071" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "admin%27--+"}'
echo ""

echo "[sqli] juiceshop-0076: %2527%2520OR%25201%253D1--+"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0076" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1--+"}'
echo ""

echo "[sqli] juiceshop-0090: 1=1"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0090" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "1=1"}'
echo ""

echo "[sqli] juiceshop-0117: %2527%2520OR%25201%253D1%2520--"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0117" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1%2520--"}'
echo ""

echo "[sqli] juiceshop-0307: %2527%2520OR%25201=1--"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0307" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201=1--"}'
echo ""

echo "[sqli] juiceshop-0319: '--%00"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0319" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "\'--%00"}'
echo ""

echo "[sqli] juiceshop-0328: 1';--"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0328" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "1\';--"}'
echo ""
