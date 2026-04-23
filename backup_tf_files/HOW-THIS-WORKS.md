# WAF Policy Testing & Validation — How This Works

## Overview

This project fires attack payloads against a WAF-protected application (Juice Shop) and validates that the WAF policy blocks them. It then produces evidence reports by correlating test results with CloudWatch WAF logs from both CloudFront and ALB.

```
                                    CloudWatch Logs
                                    ┌─────────────┐
Client ──► CloudFront WAF ──► ALB WAF ──► Juice Shop
  │              │                │            │
pytest      CF log group     ALB log group   502=crash
  │         (us-east-1)      (eu-west-1)
  │
  ▼
reports/test.json ──► validate.py ──► validation_evidence.json
                 ──► analyze.py  ──► analysis.json
                 ──► flow.py     ──► quality report + SHAP
```

---

## Architecture

| Component | What it does |
|---|---|
| `waf_requirements.yaml` | Defines 344 attack payloads (XSS, SQLi, CMDI, LFI, RFI, SSTI, base64) |
| `test_runner.py` | Fires each payload via HTTP, records HTTP status + request ID |
| `conftest.py` | Pytest configuration, fixtures, JSON export hook |
| `validate.py` | Queries CloudWatch WAF logs to prove who blocked each request |
| `analyze.py` | Produces category breakdown and findings (no ML) |
| `flow.py` | ML pipeline — trains XGBoost/GBM models on test results |

### Infrastructure

| Layer | WAF Log Group | Region |
|---|---|---|
| CloudFront WAF | `aws-waf-logs-baseline13` | `us-east-1` |
| ALB WAF | `aws-waf-logs-wpb-jenkins` | `eu-west-1` |
| Juice Shop | Docker on EC2 | `eu-west-1` |

---

## Step-by-Step Workflow

### 1. Run WAF Tests

From the `backup_tf_files/` directory on EC2:

```bash
# Quick test (console output only)
make test MODULE=test_custom_v3

# Generate JSON report (needed for analysis/validation)
make test-json MODULE=test_custom_v3
```

This fires all 344 payloads and saves results to `reports/waf_rg_hsbc_custom_v3.json`.

Each test:
- Sends a POST request with the attack payload
- Includes `X-Request-Id`, `X-Test-Id`, `X-Test-Category` headers
- Records HTTP status (403=blocked, 502=backend crash)
- Waits 2 seconds between requests

### 2. Running Tests in Background (nohup)

If your SSH session might timeout, use `nohup`:

```bash
# Start tests in background
nohup make test-json MODULE=test_custom_v3 > test.log 2>&1 &

# This returns immediately with a process ID like [1] 12345
```

**While tests are running:**

```bash
# Check if still running
jobs -l
# or
ps aux | grep pytest

# Watch progress live
tail -f test.log

# See how many tests completed so far
grep -c "TEST 1" test.log
```

**After tests complete:**

```bash
# Check exit status
cat test.log | tail -20

# Results are in:
# - test.log              (console output)
# - reports/waf_rg_hsbc_custom_v3.json  (structured JSON)
```

**If SSH disconnects during nohup:**
- SSH back in
- The process keeps running
- Check `test.log` for progress
- Results will be in `reports/` when done

**Alternative: use screen**

```bash
# Start a screen session
screen -S waf-test

# Run tests
make test-json MODULE=test_custom_v3

# Detach: press Ctrl+A then D
# SSH can disconnect safely

# Reconnect later
screen -r waf-test
```

---

### 3. Run Analysis

After tests complete, go to `ml-training/` directory:

```bash
cd ml-training
```

#### Quick Analysis (no ML, no AWS access needed)

Shows category breakdown, block rates, and findings:

```bash
make analyze REPORT=../reports/waf_rg_hsbc_custom_v3.json
```

Output:
```
======================================================================
WAF POLICY ANALYSIS — all
======================================================================
  Total tests:     344
  Blocked by WAF:  303
  Backend crashes: 41
  Block rate:      88.1%

Category      Total  Blocked  Bypassed  Crashed    Rate
──────────────────────────────────────────────────────────────────────
xss             185      177         0        8   95.7%
sqli            122      112         0       10   91.8%
ssti             10        0         0       10    0.0%
cmdi             10        3         0        7   30.0%
...
```

Results saved to: `output/analysis.json`

#### Full Analysis with Payload Details

Includes the actual payload text for each bypassed test:

```bash
make analyze-full \
  REPORT=../reports/waf_rg_hsbc_custom_v3.json \
  YAML=../modules/test_custom_v3/waf_requirements.yaml
```

Results saved to: `output/analysis.json`

---

### 4. Run Validation (Evidence Report)

This is the key step for audit evidence. It queries both CloudFront and ALB WAF CloudWatch logs to prove what actually happened for each request.

**Requires:** AWS credentials with CloudWatch Logs read access in both `us-east-1` and `eu-west-1`.

#### Validate All Results

```bash
make validate REPORT=../reports/waf_rg_hsbc_custom_v3.json
```

This queries CloudWatch for all 344 request IDs. Takes ~15-20 minutes (1-2 seconds per query, two queries per test).

#### Validate Failures + Sample of Passes (Faster)

```bash
make validate-sample REPORT=../reports/waf_rg_hsbc_custom_v3.json
```

Validates all failures + 20 random passes. Takes ~5 minutes.

#### What Validation Produces

For each test, it looks up the request ID in both WAF log groups and determines a verdict:

| Verdict | Meaning | Evidence |
|---|---|---|
| `CF_BLOCK` | CloudFront WAF blocked it (403) | CF WAF log shows BLOCK + rule name |
| `CF_ALLOW_ALB_BLOCK` | CF allowed, ALB WAF caught it (403) | Both logs present, ALB shows BLOCK |
| `CF_ALLOW_ALB_ALLOW_BACKEND_CRASH` | Both WAFs allowed, backend crashed (502) | Both logs show ALLOW — WAF gap |
| `NO_CF_LOG` | No CF WAF log found | 403 source unknown — needs review |
| `DISCREPANCY` | Log doesn't match HTTP status | Needs investigation |

Results saved to: `output/validation_evidence.json`

#### Example Evidence Entry

```json
{
  "test_id": "juiceshop-0044:positive",
  "request_id": "waf-test-7fa27222-b39f-4a8e-...",
  "http_status": 403,
  "verdict": "CF_BLOCK",
  "evidence": "CONFIRMED: CloudFront WAF blocked this request. Rule: baseline_1_3_xss_rule.",
  "cf_waf_log": {
    "source": "CloudFront WAF",
    "found": true,
    "action": "BLOCK",
    "terminating_rule_id": "baseline_1_3_xss_rule",
    "timestamp": "2026-04-23T14:30:00Z"
  },
  "alb_waf_log": {
    "source": "ALB WAF",
    "found": false
  }
}
```

---

### 5. Run ML Training (Optional)

Trains XGBoost, Gradient Boosting, and Logistic Regression models to score policy quality:

```bash
# Install dependencies (first time only)
make install

# Train on a single report
make train-single REPORT=../reports/waf_rg_hsbc_custom_v3.json
```

Output: `output/quality_waf_rg_hsbc_custom_v3.json` with quality grade (A-F), SHAP plots, and recommendations.

#### Compare Policy Versions

After testing multiple policy versions:

```bash
make compare FILES='../reports/v1.json ../reports/v2.json ../reports/v3.json'
```

Output:
```
================================================================================
POLICY VERSION COMPARISON
================================================================================
Policy                     Pass%   Block%  Crashes   Avg ms
--------------------------------------------------------------------------------
v1                          91.2%    89.5%       12     145.3
v2                          95.6%    94.1%        5     132.7
v3                          98.8%    97.4%        2     128.1
================================================================================
```

---

## All Make Commands

### From `backup_tf_files/` (WAF Testing)

| Command | What it does |
|---|---|
| `make test MODULE=test_custom_v3` | Run tests, console output only |
| `make test-json MODULE=test_custom_v3` | Run tests + save JSON report |
| `make test-report MODULE=test_custom_v3` | Run tests + save HTML report |

### From `ml-training/` (Analysis & Validation)

| Command | What it does |
|---|---|
| `make install` | Install Python dependencies |
| `make analyze REPORT=path.json` | Quick analysis — category breakdown |
| `make analyze-full REPORT=x YAML=y` | Full analysis with payload details |
| `make validate REPORT=path.json` | Validate ALL results against WAF logs |
| `make validate-sample REPORT=path.json` | Validate failures + 20 random passes |
| `make train-single REPORT=path.json` | ML training on single report |
| `make train` | ML training on all reports |
| `make compare FILES='a.json b.json'` | Compare policy versions |
| `make clean` | Delete output files |
| `make help` | Show available commands |

---

## Output Files

All outputs go to `ml-training/output/`:

| File | Source | Contents |
|---|---|---|
| `analysis.json` | `make analyze` | Category breakdown, findings |
| `validation_evidence.json` | `make validate` | Per-request WAF log evidence |
| `quality_*.json` | `make train-single` | ML quality grade, metrics |
| `shap_summary.png` | `make train-single` | Feature importance plot |
| `shap_bar.png` | `make train-single` | SHAP bar chart |
| `shap_waterfall_*.png` | `make train-single` | Per-payload SHAP explanation |
| `shap_report.json` | `make train-single` | Machine-readable SHAP data |
| `policy_comparison.json` | `make compare` | Side-by-side comparison |

---

## Uploading Results to S3

```bash
# Upload all outputs
aws s3 cp ml-training/output/ s3://waf-pytest/ml-training/output/ --recursive

# Upload just the evidence report
aws s3 cp ml-training/output/validation_evidence.json s3://waf-pytest/evidence/

# Download to local machine
aws s3 cp s3://waf-pytest/ml-training/output/ ~/Downloads/waf-output/ --recursive
```

---

## CloudWatch Insights Queries

Use these in the AWS Console under CloudWatch > Logs Insights.

**Overall stats (select CF WAF log group, us-east-1):**
```
fields @timestamp, action, httpRequest.uri
| filter @message like /waf-test-/
| stats count(*) as total,
        sum(action="ALLOW") as allowed,
        sum(action="BLOCK") as blocked
```

**Split by category (using X-Test-Category header):**
```
fields @timestamp, action
| parse @message '"X-Test-Category":"*"' as category
| parse @message '"X-Test-Id":"*"' as testId
| filter @message like /waf-test-/
| stats count(*) as total, sum(action="BLOCK") as blocked, sum(action="ALLOW") as allowed
  by category
```

**Find a specific test case:**
```
fields @timestamp, action, terminatingRuleId
| parse @message '"X-Test-Id":"*"' as testId
| filter testId = "juiceshop-0044"
```

**Find all ALB WAF blocks (select ALB log group, eu-west-1):**
```
fields @timestamp, action, terminatingRuleId
| filter @message like /waf-test-/
| filter action = "BLOCK"
| sort @timestamp asc
```

---

## Troubleshooting

### Tests run but all return 502
- Check CF origin points to the correct ALB
- Check ALB target group has healthy targets
- Check if Lambda@Edge is attached to the CF behavior

### "fixture config not found" error
- YAML has a field that Pydantic model doesn't accept
- Run: `python3 -c "import yaml; yaml.safe_load(open('modules/test_custom_v3/waf_requirements.yaml'))"` to check YAML syntax
- Check `models.py` — all fields referenced in YAML must exist in the model (or be optional)

### validate.py returns "No WAF log found"
- Check the time window — WAF logs may be delayed by a few minutes
- Verify the log group name is correct
- Verify AWS credentials have `logs:StartQuery` and `logs:GetQueryResults` permissions
- CloudFront WAF logs are in `us-east-1`, ALB WAF logs are in `eu-west-1`

### nohup process seems stuck
```bash
# Check if process is still running
ps aux | grep pytest

# Check last output
tail -20 test.log

# Kill if needed
kill <process-id>
```
