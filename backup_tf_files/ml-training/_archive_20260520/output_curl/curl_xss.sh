#!/bin/bash
# WAF Bypass Test — XSS (8 payloads)
# Run: bash curl_xss.sh

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

echo "[xss] juiceshop-0014: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0014" \
  -H "X-Test-Category: xss" \
  -d '{"content": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'
echo ""

echo "[xss] juiceshop-0031: "><img src=x o%6ener%72=alert(1)>"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0031" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\\"><img src=x o%6ener%72=alert(1)>"}'
echo ""

echo "[xss] juiceshop-0037: <scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0037" \
  -H "X-Test-Category: xss" \
  -d '{"content": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>"}'
echo ""

echo "[xss] juiceshop-0057: %27%23"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0057" \
  -H "X-Test-Category: xss" \
  -d '{"content": "%27%23"}'
echo ""

echo "[xss] juiceshop-0104: '#"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0104" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\'#"}'
echo ""

echo "[xss] juiceshop-0184: setTimeout('%61lert(1)',1000)"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0184" \
  -H "X-Test-Category: xss" \
  -d '{"content": "setTimeout(\'%61lert(1)\',1000)"}'
echo ""

echo "[xss] juiceshop-0205: &#x3C;!--%2Balert('Payload7')%2B--&#x3E;"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0205" \
  -H "X-Test-Category: xss" \
  -d '{"content": "&#x3C;!--%2Balert(\'Payload7\')%2B--&#x3E;"}'
echo ""

echo "[xss] juiceshop-0339: '||"
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0339" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\'||"}'
echo ""
