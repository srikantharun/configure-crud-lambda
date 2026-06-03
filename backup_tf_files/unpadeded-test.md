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

