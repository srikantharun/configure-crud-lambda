#!/bin/bash
#
# WAF baseline test runbook - 6 placements end-to-end.
#
# Sequence per placement:
#   1. make test-clean
#   2. copy the GET- or POST-shaped waf_requirements.yaml
#   3. export placement env vars
#   4. make test-json (foreground - so the report file exists before we mv it)
#   5. mv report into $TEST_RUN_DIR
#   6. cd to ml-training, make validate (foreground, ~20 min)
#   7. sleep 60 (CloudWatch indexing buffer)
#   8. copy the validate log into $EVIDENCE_IN
#   9. nohup pull_raw_cloudwatch.py & ; sleep 180 (let the pull get going
#      before the next placement starts)
#
# Run on the juice-shop EC2:
#   sudo su -
#   bash run_all_placements.sh
#
# Override the run date if needed:
#   RUN_DATE=20260604 bash run_all_placements.sh
#
set -eo pipefail

# ---- top-level config ----------------------------------------------------
RUN_DATE="${RUN_DATE:-$(date +%Y%m%d)}"
TF_DIR="${TF_DIR:-/root/terraform-aws-fms-baseline-1_3}"
ML_DIR="$TF_DIR/ml-training"

ENDPOINT="${ENDPOINT:-https://dlpaasrngb6ue.cloudfront.net}"
WAF_LOG_GROUP="${WAF_LOG_GROUP:-aws-waf-logs-baseline13}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-976629938830}"
MODULE="${MODULE:-waf_rg_hsbc_custom_v3}"

TEST_RUN_DIR="$HOME/test-run-$RUN_DATE"
EVIDENCE_IN="$HOME/baseline_evidence/input"
EVIDENCE_OUT="$HOME/baseline_evidence/output"
LOG_DIR="$TEST_RUN_DIR/logs"

mkdir -p "$TEST_RUN_DIR" "$EVIDENCE_IN" "$EVIDENCE_OUT" "$LOG_DIR"

GET_YAML="modules/$MODULE/waf_requirements-basedon-getyaml"
POST_YAML="modules/$MODULE/waf_requirements-basedon-postyaml"
TARGET_YAML="modules/$MODULE/waf_requirements.yaml"

banner() {
    echo
    echo "============================================================"
    echo " $1"
    echo " $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
}

# ---- venv ----------------------------------------------------------------
banner "Activating mltest venv"
cd "$ML_DIR"
# venv activate scripts can reference unset vars, so don't combine with -u
source mltest/bin/activate
echo "Python: $(which python3)"
echo "Run date: $RUN_DATE"
echo "Test reports go to: $TEST_RUN_DIR"
echo "Evidence (raw CW) goes to: $EVIDENCE_OUT"

# =========================================================================
# 1/6 - GET / query string
# =========================================================================
banner "1/6  GET  placement=query"

cd "$TF_DIR"
make test-clean
cp "$GET_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "

export WAF_TEST_GET_PLACEMENT=query
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml

make test-json MODULE=$MODULE METHOD=get WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_get_qs.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_get_qs.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_get_qs.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-get_qs.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles get_querystring \
    --verdicts CF_ALLOW_ALB_ALLOW,CF_ALLOW_ALB_BLOCK,NO_CF_LOG \
    > "$LOG_DIR/pull_get_qs.log" 2>&1 &
sleep 180

# =========================================================================
# 2/6 - GET / header
# =========================================================================
banner "2/6  GET  placement=header"

cd "$TF_DIR"
make test-clean
cp "$GET_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "
export REQ_HEAD=" "

export WAF_TEST_GET_PLACEMENT=header
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml
export REQ_HEAD="X-REQUEST_INJECTION"

make test-json MODULE=$MODULE METHOD=get WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_get_header.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_get_header.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_get_header.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-get_header.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles get_with_header \
    --verdicts CF_ALLOW_ALB_ALLOW,CF_ALLOW_ALB_BLOCK,NO_CF_LOG \
    > "$LOG_DIR/pull_get_header.log" 2>&1 &
sleep 180

# =========================================================================
# 3/6 - GET / cookie
# =========================================================================
banner "3/6  GET  placement=cookie"

cd "$TF_DIR"
make test-clean
cp "$GET_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "

export WAF_TEST_GET_PLACEMENT=cookie
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml

make test-json MODULE=$MODULE METHOD=get WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_get_cookie.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_get_cookie.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_get_cookie.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-get_cookie.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles get_with_cookie \
    --verdicts CF_ALLOW_ALB_ALLOW \
    > "$LOG_DIR/pull_get_cookie.log" 2>&1 &
sleep 180

# =========================================================================
# 4/6 - GET / uri
# =========================================================================
banner "4/6  GET  placement=uri"

cd "$TF_DIR"
make test-clean
cp "$GET_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "

export WAF_TEST_GET_PLACEMENT=uri
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml

make test-json MODULE=$MODULE METHOD=get WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_get_uri.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_get_uri.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_get_uri.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-get_uri.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles get_with_url \
    --verdicts CF_ALLOW_ALB_ALLOW \
    > "$LOG_DIR/pull_get_uri.log" 2>&1 &
sleep 180

# =========================================================================
# 5/6 - POST / query string
# =========================================================================
banner "5/6  POST  placement=query"

cd "$TF_DIR"
make test-clean
cp "$POST_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_POST_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "

export WAF_TEST_POST_PLACEMENT=query
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml

make test-json MODULE=$MODULE METHOD=post WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_post_qs.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_post_qs.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_post_qs.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-post_qs.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles post_run1 \
    --verdicts CF_ALLOW_ALB_ALLOW \
    > "$LOG_DIR/pull_post_qs.log" 2>&1 &
sleep 180

# =========================================================================
# 6/6 - POST / body
# =========================================================================
banner "6/6  POST  placement=body"

cd "$TF_DIR"
make test-clean
cp "$POST_YAML" "$TARGET_YAML"

export WAF_TEST_GET_PLACEMENT=" "
export WAF_TEST_POST_PLACEMENT=" "
export WAF_TEST_REQUIREMENTS_FILENAME=" "

export WAF_TEST_POST_PLACEMENT=body
export WAF_TEST_REQUIREMENTS_FILENAME=waf_requirements.yaml

make test-json MODULE=$MODULE METHOD=post WAF_ENDPOINT=$ENDPOINT WAF_LOG_GROUP=$WAF_LOG_GROUP AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID > "$LOG_DIR/test_post_body.log" 2>&1
mv "$TF_DIR/reports/${MODULE}.json" "$TEST_RUN_DIR/${MODULE}_post_body.json"

cd "$ML_DIR"
make validate REPORT="$TEST_RUN_DIR/${MODULE}_post_body.json"
sleep 60

cp "$ML_DIR/output/"validate*.log "$EVIDENCE_IN/validate-post_body.log"

cd "$HOME"
nohup python3 pull_raw_cloudwatch.py \
    --input-dir baseline_evidence/input \
    --output-dir baseline_evidence/output \
    --profiles post_run2 \
    --verdicts CF_ALLOW_ALB_ALLOW \
    > "$LOG_DIR/pull_post_body.log" 2>&1 &
sleep 180

# =========================================================================
banner "DONE - 6/6 placements dispatched"
echo
echo "Pull jobs may still be running in the background. Check:"
echo "  pgrep -af pull_raw_cloudwatch.py"
echo "  tail -f $LOG_DIR/pull_*.log"
echo
echo "When all pull jobs finish, evidence will be under:"
echo "  $EVIDENCE_OUT/raw_logs/"
echo
echo "Validate reports are in:"
echo "  $TEST_RUN_DIR/"
echo
echo "All logs are in:"
echo "  $LOG_DIR/"
