  #!/bin/bash
  # fetch_webacl.sh
  # Fetch ONE AWS WAFv2 WebACL (CLOUDFRONT scope) and print a summary.
  # Run twice — once per account — with a different LABEL each time.
  set -euo pipefail

  REGION=us-east-1
  SCOPE=CLOUDFRONT
  OUT=./webacl_diff
  mkdir -p "$OUT"

  usage() {
      cat <<EOF
  Usage:
    $0 --list                              # list all WebACLs in the current account
    $0 <LABEL> <WEBACL_NAME>               # fetch and dump JSON + summary
    $0 <LABEL>                             # fetch using a default name

  Examples:
    $0 --list
    $0 1.1   FMManagedWebACLV2-Baseline_global_cyberwasp_version_1_1_block-1778666570727
    $0 1.3b  FMManagedWebACLV2-baseline_1_3_block_v1-1776262662672

  LABEL is just a string used in output filenames (e.g. 1.1, 1.3b).
  Output: \$OUT/policy_<LABEL>.json
  EOF
      exit 1
  }

  # --- List mode -----------------------------------------------------------
  if [[ "${1:-}" == "--list" || $# -lt 1 ]]; then
      if [[ "${1:-}" == "--list" ]]; then
          echo "WebACLs in scope $SCOPE / region $REGION:"
          echo "(current account: $(aws sts get-caller-identity --query Account --output text))"
          aws wafv2 list-web-acls --scope $SCOPE --region $REGION \
              --query 'WebACLs[].[Name,Id]' --output table
          exit 0
      fi
      usage
  fi

  LABEL="$1"
  NAME="${2:-}"

  # --- Resolve name --------------------------------------------------------
  if [[ -z "$NAME" ]]; then
      echo "ERROR: WebACL name required as second argument (or run --list to find it)" >&2
      exit 1
  fi

  ID=$(aws wafv2 list-web-acls --scope $SCOPE --region $REGION \
      --query "WebACLs[?Name=='$NAME'].Id" --output text)

  if [[ -z "$ID" || "$ID" == "None" ]]; then
      echo "ERROR: WebACL '$NAME' not found in account $(aws sts get-caller-identity --query Account --output text)" >&2
      echo "Run '$0 --list' to see what's available in this account." >&2
      exit 1
  fi

  ACCT=$(aws sts get-caller-identity --query Account --output text)
  JSON="$OUT/policy_${LABEL}.json"

  echo "Account:  $ACCT"
  echo "WebACL:   $NAME"
  echo "Id:       $ID"
  echo "Saving:   $JSON"
  echo

  aws wafv2 get-web-acl --scope $SCOPE --region $REGION \
      --name "$NAME" --id "$ID" > "$JSON"

  # --- Summary -------------------------------------------------------------
  echo "=== Managed Rule Groups & versions ==="
  jq -r '.WebACL.Rules[]
      | select(.Statement.ManagedRuleGroupStatement)
      | [.Priority,
         .Statement.ManagedRuleGroupStatement.VendorName,
         .Statement.ManagedRuleGroupStatement.Name,
         (.Statement.ManagedRuleGroupStatement.Version // "DEFAULT"),
         ((.Statement.ManagedRuleGroupStatement.RuleActionOverrides // []) | length | tostring + " overrides"),
         (.OverrideAction | keys[0])]
      | @tsv' "$JSON" | column -t -s $'\t'

  echo
  echo "=== RuleActionOverrides (per managed group) ==="
  jq -r '.WebACL.Rules[]
      | select(.Statement.ManagedRuleGroupStatement)
      | .Statement.ManagedRuleGroupStatement
      | select((.RuleActionOverrides // []) | length > 0)
      | .Name as $group
      | .RuleActionOverrides[]
      | [$group, .Name, (.ActionToUse | keys[0])]
      | @tsv' "$JSON" | column -t -s $'\t'

  echo
  echo "=== Custom (non-managed) rules ==="
  jq -r '.WebACL.Rules[]
      | select(.Statement.ManagedRuleGroupStatement | not)
      | [.Priority, .Name, (.Action | keys[0] // (.OverrideAction | keys[0]))]
      | @tsv' "$JSON" | column -t -s $'\t'

  echo
  echo "Raw JSON: $JSON  (send this back for the cross-policy diff)"

  How to use it

  chmod +x fetch_webacl.sh

  # --- in account A (1.1) ---
  aws sso login --profile <prod-account>     # or however you auth
  ./fetch_webacl.sh --list                   # confirm the WebACL name
  ./fetch_webacl.sh 1.1 FMManagedWebACLV2-Baseline_global_cyberwasp_version_1_1_block-1778666570727
  #  -> webacl_diff/policy_1.1.json

  # --- switch accounts, in account B (1.3b) ---
  aws sso login --profile <other-account>
  ./fetch_webacl.sh --list
  ./fetch_webacl.sh 1.3b FMManagedWebACLV2-baseline_1_3_block_v1-1776262662672
  #  -> webacl_diff/policy_1.3b.json
