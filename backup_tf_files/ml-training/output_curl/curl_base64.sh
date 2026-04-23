#!/bin/bash
# WAF Bypass Test — BASE64 (2 payloads)
# Run: bash curl_base64.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[base64] juiceshop-0036: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0036" \
  -H "X-Test-Category: base64" \
  -d '{"content": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'
echo ""

echo "[base64] juiceshop-0098: JyBPUiAnMT0nJz0nMQ=="
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0098" \
  -H "X-Test-Category: base64" \
  -d '{"content": "JyBPUiAnMT0nJz0nMQ=="}'
echo ""
