#!/bin/bash
  # size_anti_bypass.sh
  # Goal: prove that a size-restriction BLOCK rule (present in 1.3) catches
  # requests where the attack payload is pushed PAST the WAF inspection limit
  # (8KB / 64KB). Without that rule (1.1), WAF only sees the first N bytes,
  # never reaches the attack, and lets the request through.
  #
  # Usage:
  #   ENDPOINT=https://<1.1 cloudfront domain> ./size_anti_bypass.sh
  #   ENDPOINT=https://<1.3 cloudfront domain> ./size_anti_bypass.sh
  set -u
  ENDPOINT="${ENDPOINT:?set ENDPOINT, e.g. ENDPOINT=https://dlpaasrngb6ue.cloudfront.net}"
  URI_PATH="/rest/user/login"

  # Attack: simple SQLi, reliably blocked by 1.1 at normal size (SQLi rule group)
  ATTACK="' OR 1=1--"

  # Padding strings (single line, no newlines so WAF sees one giant field)
  PAD_70K=$(printf 'A%.0s' $(seq 1 71680))   # > 64KB body inspection limit
  PAD_10K=$(printf 'A%.0s' $(seq 1 10240))   # >  8KB header / cookie limit

  TAG="anti-bypass-$(date +%Y%m%d-%H%M)"
  echo "ENDPOINT: $ENDPOINT"
  echo "TAG:      $TAG"
  echo

  run () {
      local label="$1" rid="$TAG-$2-$RANDOM"
      shift 2
      echo "--- $label ---"
      echo "request_id: $rid"
      curl -sS -o /tmp/$rid.body -w 'HTTP %{http_code}  size_dl=%{size_download}\n' \
          -H "X-Request-Id: $rid" "$@"
      echo
  }

  # 1. POST body > 64KB - attack at the end of the JSON
  run "POST body  > 64KB" "body" \
      -X POST "$ENDPOINT$URI_PATH" \
      -H "Content-Type: application/json" \
      --data-raw "{\"padding\":\"$PAD_70K\",\"email\":\"$ATTACK\",\"password\":\"x\"}"

  # 2. GET single header > 8KB - attack at the end of the header value
  run "GET header > 8KB" "header" \
      "$ENDPOINT$URI_PATH" \
      -H "X-Pad-Test: ${PAD_10K}${ATTACK}"

  # 3. GET Cookie > 8KB - attack at the end of the cookie value
  run "GET cookie > 8KB" "cookie" \
      "$ENDPOINT$URI_PATH" \
      -H "Cookie: pad=${PAD_10K}; session=${ATTACK}"

  echo
  echo "Look these up in CloudWatch Logs Insights:"
  echo "  fields @timestamp, action, terminatingRuleId,"
  echo "         terminatingRuleMatchDetails.0.location,"
  echo "         terminatingRuleMatchDetails.0.matchedFieldName"
  echo "  | filter @message like /$TAG/"

  How to read the results

  ┌──────────────────────┬────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────┐
  │       Scenario       │        Expected on 1.1 (no size-BLOCK rule)        │          Expected on 1.3 (with size-BLOCK rule)           │
  ├──────────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
  │ 1 — POST body > 64KB │ HTTP 200 (attack outside inspection window → leak) │ HTTP 403 with terminatingRuleId = <size-restriction rule> │
  ├──────────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
  │ 2 — Header > 8KB     │ HTTP 200                                           │ HTTP 403 with terminatingRuleId = <size-restriction rule> │
  ├──────────────────────┼────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────┤
  │ 3 — Cookie > 8KB     │ HTTP 200                                           │ HTTP 403 with terminatingRuleId = <size-restriction rule> │
  └──────────────────────┴────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────┘

  If 1.1 returns 200 on any of the three → that's your gap proof (attacker padded their way past).
  If 1.3 returns 403 with the size-restriction rule named → that's the anti-bypass control working.

  Sanity-check first (recommended)

  Before running the 6 padded curls, fire the un-padded attack once against 1.1 to confirm the chosen payload is blocked at normal size — otherwise a 1.1 "leak" on the padded test could just mean 1.1 never caught that pattern in the first place.

  curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
    -H "X-Request-Id: $TAG-control" \
    -X POST "$ENDPOINT$URI_PATH" \
    -H "Content-Type: application/json" \
    --data-raw "{\"email\":\"$ATTACK\",\"password\":\"x\"}"
  Expected on 1.1: HTTP 403 (SQLi rule catches ' OR 1=1--). If that's not 403, swap ATTACK to a different known-blocked payload from waf_requirements.yaml before running the padded set.

===

┌────────┬─────────────────────────┬────────────────────┐
  │ Family │ Unique test_ids leaking │ Share of 186 leaks │
  ├────────┼─────────────────────────┼────────────────────┤
  │ XSS    │                      96 │                52% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ SQLi   │                      55 │                30% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ RFI    │                      11 │                 6% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ SSTI   │                      10 │                 5% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ CMDI   │                       8 │                 4% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ LFI    │                       4 │                 2% │
  ├────────┼─────────────────────────┼────────────────────┤
  │ Base64 │                       2 │                 1% │


 Almost all leaks fall in get_header placement — many tests block on 5 of 6 placements and only leak on header. That's a single concentrated weakness: the rules aren't applying ALL_HEADERS or SingleHeader inspection to the same depth as body/QS.

  ---
  1. SQLi — 55 leakers

  Why they leak

  Three encoding tricks the current SQLi rule group misses:

  - Comment terminators only: admin' --, admin' #, --+ — pure comments without a clear injection clause.
  - Double URL-encoding: %2527%2520OR%25201%253D1-- (i.e. %25 first decodes to % then to '). Default URL_DECODE runs once; SQLi rule misses doubly-encoded.
  - Spaced/parenthesised boolean: ') OR ('1'='1, ' OR ' + 1=1 + --.

  Recommended regex (RegexPatternSet)

  Apply to: BODY, JSON_BODY (MATCH_PATTERN: ALL), QUERY_STRING, SINGLE_HEADER: cookie, ALL_HEADERS. Use two URL_DECODE text transforms in sequence to defeat double-encoding.

  # 1.  ' OR / AND with optional parens/spaces, comment optional
  (?i)(?:^|[\s\(\)'\"])(?:'|%27)\s*[\)\]]?\s*(?:or|and)\s+['\"]?[\w\d]+['\"]?\s*=\s*['\"]?[\w\d]+

  # 2.  Lone quote + comment terminator (admin'-- / admin'#)
  (?i)['\"](?:\s|%20|\+)*(?:-{2,}|#)

  # 3.  Stacked queries / UNION
  (?i)(?:union(?:\s|%20|\+|/\*.*?\*/)+select)|;\s*(?:drop|insert|update|delete)\b

  Priority order: place this after the AWS managed SQLiRuleSet (so managed catches first), but before Default_Action. WCU ≈ 50.

  Caveat

  The comment-terminator regex (#2) can fire on legitimate input like comment'-- ignore me. Run in COUNT mode for 7 days, watch the match rate against production traffic, then promote to BLOCK only if false-positive rate is acceptable.

  ---
  2. XSS — 96 leakers (the biggest single win)

  Why they leak

  Almost all 96 are in get_header only, and the bypass patterns fall into 5 buckets:

  - HTML-entity-encoded tags: &lt;script&gt;, &#60;script&#62;
  - Double URL-encoded tags: %253Cscript%253E
  - Unicode escape: %u003Cscript
  - Charcode bypass inside alert(): alert\x28, alert\u0028, alert&#40;
  - Nested confusion: <scr<script>ipt> — AWS rule probably normalises by removing inner <script>, leaving outer benign

  Recommended regex

  Apply to: ALL_HEADERS, SINGLE_HEADER: cookie, BODY, JSON_BODY, QUERY_STRING, URI_PATH. Transforms: URL_DECODE, URL_DECODE, HTML_ENTITY_DECODE, LOWERCASE.

  # 1.  <script> or </script> after multi-layer decoding
  (?i)<\s*/?\s*script[\s>]

  # 2.  Event-handler injection
  (?i)\bon(?:click|load|error|mouseover|focus|blur|submit|change|key(?:up|down|press))\s*=

  # 3.  alert / prompt / confirm with any charcode-style paren
  (?i)\b(?:alert|prompt|confirm|eval)\s*(?:\(|\\x28|\\u0028|%28)

  # 4.  javascript: scheme
  (?i)javascript\s*:\s*\S

  Priority: put this first in the custom rule group so it fires before AWS-managed XSS catches the cleaner cases. WCU ≈ 60.

  Caveat

  on...= is the highest FP-risk pattern (legitimate JS framework forms set onclick= in form fields). Strongly recommend COUNT mode for 2 weeks against prod traffic before BLOCK.

  ---
  3. RFI / "PHP-insecure" — 11 leakers (all of them)

  Why they leak

  - URL-encoded scheme: %68%74%74%70%3a%2f%2f decodes to http:// only once; needs two passes.
  - Backslash variants: \\attacker.com\backdoor.txt, %5c%5c.
  - Null-byte and path tricks: http://evil.com%00/shell.php, http://ev%69l.com/shell.php (encoded i).

  Recommended regex

  Apply to: all 6 placements (these are universally dangerous). Transforms: URL_DECODE, URL_DECODE, LOWERCASE.

  # 1.  Remote inclusion via http(s):// in user-controlled fields
  (?i)(?:^|[\s'\"=\?\&\#])https?:\/\/[a-z0-9.\-]+\.[a-z]{2,}\/

  # 2.  SMB/UNC paths
  \\\\[a-z0-9.\-]+\\

  # 3.  PHP wrappers used as RFI/LFI vector
  (?i)(?:php|data|expect|file|zip|glob|phar):\/\/

  # 4.  Encoded-character obfuscation inside a hostname
  (?i)https?:\/\/[a-z0-9.\-]*%[0-9a-f]{2}[a-z0-9.\-]*\.[a-z]{2,}

  Priority: place first in the cyberwasp-equivalent custom rule group (these are unambiguously hostile patterns). WCU ≈ 45.

  ---
  4. SSTI — 10 leakers (all of them)

  Why they leak

  Template-injection sigils aren't in standard AWS WAF rule groups: ${...}, {{...}}, <%= %>, @(...). All 10 SSTI test_ids leak in every placement.

  Recommended regex

  Apply to: all 6 placements. Transforms: URL_DECODE, URL_DECODE.

  # 1.  Jinja / Twig / Handlebars
  (?i)\{\{\s*[\w\d.()*+/\-]{1,50}\s*\}\}

  # 2.  Shell / JSP-EL / Spring SpEL / Freemarker
  (?i)(?:\$|#)\{\s*[\w\d.()*+/\-]{1,50}\s*\}

  # 3.  ERB / ASP / Java <%= %>
  <%\s*=\s*

  # 4.  Freemarker / dangerous assign
  (?i)<#assign[^>]+freemarker\.template

  Priority: after managed rules, before default. WCU ≈ 30.

  Caveat

  #1 ({{...}}) and #2 (${...}) can fire on legitimate template snippets uploaded as user content (docs, code-snippet apps). Must COUNT-test on production. Consider scoping by path if you have endpoints that legitimately accept template strings.

  ---
  5. CMDI — 8 leakers

  Why they leak

  - IFS bypass: ${IFS} replaces spaces in shell commands — most CMDI rules look for explicit spaces.
  - Backtick execution: `id`, `uname -a`.
  - Double-encoded operators: %2526%2526 → &&, %3B → ;.

  Recommended regex

  Apply to: all 6 placements. Transforms: URL_DECODE, URL_DECODE.

  # 1.  Command separators + common binaries
  (?i)(?:^|[\s;&|`$\(])(?:id|whoami|uname|cat|nc|wget|curl|sh|bash|ksh|powershell)\b

  # 2.  IFS bypass / brace expansion
  (?i)\$(?:\{IFS\}|IFS)

  # 3.  Backtick command substitution
  \`[^\`]{1,80}\`

  # 4.  Process substitution and pipes
  (?i)(?:\$\(|<\()\s*(?:id|whoami|uname|cat)

  Priority: after managed Linux/Unix rules. WCU ≈ 40.

  ---
  6. LFI — 4 leakers

  Why they leak

  - Mixed-encoding traversal: ..%c0%af..%c0%afetc%c0%afpasswd (overlong UTF-8 for /).
  - Multi-dot variants: ....%5C....%5C....%5Cetc%5Cpasswd.
  - PHP wrapper as LFI: data://text/plain;base64,..., expect://id.

  Recommended regex

  Already partly covered by RFI rule #3 above (the (php|data|expect|file): rule). Plus:

  # 1.  Path traversal (any form: forward, back, encoded, overlong)
  (?:\.{2,}|%2[eE]{1,2}){1,}[/\\%]
  (?:%c0%af|%c0%2f|%c1%9c)

  # 2.  Sensitive files
  (?i)/etc/(?:passwd|shadow|hosts|fstab)|/proc/self/environ|c:\\\\windows\\\\win\.ini

  Priority: with RFI rules. WCU ≈ 20.

  ---
  7. Base64 — 2 leakers (lowest priority)

  Hardest family to write a generic regex for — base64 looks like normal alphanumeric noise. Three options, none perfect:

  - A. Known-signature regex: match the base64 prefixes of common attack starts. e.g. PHNjcmlwdD (<script), JyBPUiAn (' OR '), PD9waHA (<?php). Low FP but easy for attackers to vary by adding leading whitespace.
  - B. Decode-then-inspect via Lambda@Edge: more powerful but adds latency and another moving part.
  - C. Accept the residual risk (2 tests, both XSS/SQLi cousins) and rely on managed rules to catch the decoded payload server-side.

Then each rule shrinks from "lots of byte_match per (string × placement × transformation)" to "one regex_pattern_set_reference_statement per placement, with all 5 transformations chained":

  Before (~70 byte_match blocks for php rule)

  statement { byte_match_statement { search_string = "php" field=uri_path transform=URL_DECODE } }
  statement { byte_match_statement { search_string = "php" field=uri_path transform=UTF8_TO_UNICODE } }
  statement { byte_match_statement { search_string = "php" field=uri_path transform=HEX_DECODE } }
  ... × 70+ permutations ...

  After (5 regex_pattern_set_reference_statements per rule)

  statement {
    regex_pattern_set_reference_statement {
      arn = aws_wafv2_regex_pattern_set.owasp_php_signatures.arn
      field_to_match { uri_path {} }
      text_transformation { priority = 0  type = "URL_DECODE" }
      text_transformation { priority = 1  type = "HTML_ENTITY_DECODE" }
      text_transformation { priority = 2  type = "HEX_DECODE" }
      text_transformation { priority = 3  type = "BASE64_DECODE" }
      text_transformation { priority = 4  type = "UTF8_TO_UNICODE" }
    }
  }
  # ... same statement repeated 4 more times with body, query_string, cookies, headers ...

┌─────────────┬─────────────────────────────────────────────────────────────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────┬────────────────┐
  │    Rule     │                                       Before                                        │                                           After                                           │     Saving     │
  ├─────────────┼─────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ 3 (PHP)     │ ~110 byte_match_statement blocks (every string × every placement × every transform) │ 7 regex_pattern_set_reference_statement + 1 trailing byte_match for /                     │ biggest        │
  ├─────────────┼─────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ 4 (RFI/LFI) │ ~40 byte_match in Group 1 + dynamic mauth/https checks                              │ 3 regex_pattern_set_reference_statement in Group 1 + 2 in not_statement + 2 dynamic mauth │ second-biggest │
  ├─────────────┼─────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ 6 (SQLi)    │ 8 sqli_match_statement (4 placements × 2 transforms)                                │ 4 sqli_match_statement, chained transforms per placement                                  │ smaller        │
  ├─────────────┼─────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ 7 (XSS)     │ 25 xss_match_statement (5 placements × 5 transforms)                                │ 5 xss_match_statement, all 5 transforms chained per placement                             │ medium         │
  ├─────────────┼─────────────────────────────────────────────────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────┼────────────────┤
  │ 0, 1, 2, 5  │ unchanged                                                                           │ unchanged                                                                                 │ —              │
  └─────────────┴─────────────────────────────────────────────────────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────┴────────────────┘

 ┌───────────────────────────────────────┬──────────────────────────────────┬───────────────────────┬─────────────────────────────────────────────────────────────┐
  │                 Rule                  │ Before (approx, from your paste) │ After (exact, grep'd) │                            Delta                            │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Module + IP sets + rule-group header  │ ~1–45                            │ 1–168                 │ grew because of 5 new aws_wafv2_regex_pattern_set resources │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 0 owasp-detect-admin-access      │ ~46–105                          │ 169–225               │ unchanged                                                   │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 1 owasp-detect-bad-auth-tokens   │ ~106–165                         │ 226–292               │ unchanged                                                   │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 2 owasp-detect-blacklisted-ips   │ ~166–200                         │ 293–338               │ unchanged                                                   │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 3 owasp-detect-php-insecure      │ ~201–1230 (~1030 lines)          │ 339–673 (335 lines)   │ ✂️  ~700 lines removed                                       │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 4 owasp-detect-rfi-lfi-traversal │ ~1231–1755 (~525 lines)          │ 674–903 (230 lines)   │ ✂️  ~295 lines removed                                       │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 5 owasp-detect-ssi               │ ~1756–1870                       │ 904–1063              │ unchanged                                                   │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 6 owasp-mitigate-sqli            │ ~1871–1995 (~125 lines)          │ 1064–1165 (102 lines) │ ✂️  ~23 lines (4 fewer statements, chained transforms)       │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ Rule 7 owasp-mitigate-xss             │ ~1996–2345 (~350 lines)          │ 1166–1346 (180 lines) │ ✂️  ~170 lines (20 fewer statements)                         │
  ├───────────────────────────────────────┼──────────────────────────────────┼───────────────────────┼─────────────────────────────────────────────────────────────┤
  │ TOTAL                                 │ ~2345 lines (estimate)           │ 1346 lines (exact)    │ ~1000 lines removed                                         │
  └───────────────────────────────────────┴──────────────────────────────────┴───────────────────────┴─────────────────────────────────────────────────────────────┘
