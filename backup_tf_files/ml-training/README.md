# WAF Baseline Analytics

Compare WAF managed-rule-group baseline policies (1.1, 1.3, 1.3b) across
the five request placements (POST / GET-QS / GET-Cookie / GET-URI /
GET-Header) and produce a manager-facing workbook that shows where each
policy blocks, leaks, regresses, or gains coverage.

This folder is **not** an ML training pipeline anymore — it is a
two-stage reporting tool driven entirely by `make`.

---

## Quick Start

```bash
# 1. One-time setup (creates ./mltest venv + installs deps)
make install

# 2. Drop the day's evidence JSONs into runs/<date>_run/
#    Files expected:
#      validate_baseline_1.1_{post,get_qs,get_cookie,get_uri,get_header}.json
#      validate_baseline_1.3_{post,get_qs,get_cookie,get_uri,get_header}.json
#      validate_baseline_1.3b_{post,get_qs,get_cookie,get_uri,get_header}.json

# 3. Build the report
make comparison RUN_DATE=20260521

# 4. Open the result
open runs/comparison_1.1_vs_1.3_vs_1.3b_FORMULAS_FIXED_20260521.xlsx
```

You do **not** need to `source mltest/bin/activate` — every `make`
target calls the venv's python directly.

---

## Targets

| Target | Purpose |
|---|---|
| `make install` | Create `mltest/` venv (if missing) and install `requirements.txt` into it |
| `make validate REPORT=…` | Run validation against a pytest JSON report, collect CF + ALB WAF evidence, write a `validate_baseline_*.json` |
| `make validate-sample REPORT=…` | Same as `validate` but only checks all failures + 20 random passes (faster spot-check) |
| `make build-xlsx RUN_DATE=YYYYMMDD` | Convert the 15 evidence JSONs in `runs/<date>_run/` into 15 per-(policy, placement) audit XLSXs |
| `make comparison RUN_DATE=YYYYMMDD` | Build the single consolidated workbook (`comparison_1.1_vs_1.3_vs_1.3b_FORMULAS_FIXED_<date>.xlsx`) |
| `make clean` | Wipe `output/` and `__pycache__/` |
| `make help` | Show usage |

---

## `make validate`

Takes a pytest JSON report, looks up each test's CloudFront + ALB WAF
log entries by `request_id`, and emits a structured JSON.

```bash
make validate REPORT=../reports/test_baseline_1.3b_get_uri.json
```

Inputs (set via env / Makefile override if non-default):

| Variable | Default | What it is |
|---|---|---|
| `REPORT` | _(required)_ | path to the pytest JSON report |
| `CF_LOG_GROUP` | `aws-waf-logs-baseline13` | CloudFront WAF log group |
| `CF_REGION` | `us-east-1` | |
| `ALB_LOG_GROUP` | `aws-waf-logs-wpb-jenkins` | ALB WAF log group |
| `ALB_REGION` | `eu-west-1` | |
| `OUTPUT_DIR` | `output` | where the JSON is written |

Output JSON structure (per test):

```json
{
  "test_id":      "juiceshop-0042",
  "request_id":   "waf-test-...",
  "verdict":      "CF_BLOCK | CF_ALLOW_ALB_BLOCK | CF_ALLOW_ALB_ALLOW | NO_CF_LOG",
  "cf_waf_log":   { "terminating_rule_id": ..., "action": ..., ... },
  "alb_waf_log":  { ... }
}
```

The verdict is the single piece of data downstream tooling cares
about. Once you have validated all 15 (policy × placement) combinations
for a date, drop them into `runs/<date>_run/` and move on to
`make comparison`.

---

## `make comparison`

Builds the manager-facing workbook from the 15 JSONs in
`runs/<date>_run/`. The workbook has:

### Tabs

| Tab | Contents |
|---|---|
| **Definitions** | How to read the workbook + verification steps + known caveats |
| **Summary** | <p>**Left** — per-ruleset counts (`both` / `1.3 only` / `1.1 only (REGRESSION)`) via `COUNTIF` formulas, one row per ruleset × comparison. Plus CF\_BLOCK share by ruleset (% of 1720) and by ruleset × placement (% of 344).</p><p>**Right (col H+)** — "Where the leaks live": for each of the 15 (policy, placement) cells, a breakdown of the leaked tests by attack family (xss / sqli / cmdi / lfi / rfi / Uncategorized) with TOTAL.</p> |
| **Common, SQLi, KnownBadInputs, Windows, Linux, Unix, PHP, AdminProtection, WordPress, cyberwasp, owasp-top10** | Per-ruleset analytics. Each row is a `juiceshop-NNNN` test. Columns C–G compare 1.1 vs 1.3 across the 5 placements; columns H–L compare 1.1 vs 1.3b. Cells are nested-IF formulas resolved on open. Green = `both` or `1.3 only`. Red = `1.1 only (REGRESSION)`. |
| **RAW\_\<policy\>\_\<placement\>** | 15 raw-data tabs (one per JSON). Columns: `test_id`, `request_id`, `verdict`, `rule_short`, `rule_id`, `payload`, `cf_action`, `cf_timestamp`, `attack_family`. These tabs power every formula on the analytic tabs. |

### Verification workflow

Every analytic cell can be traced back to a CloudWatch log entry in
three steps (described in full on the Definitions tab):

1. Pick a cell on a per-ruleset tab. Note the test_id (col A) and the
   placement (col header).
2. Open the matching `RAW_<policy>_<placement>` tab.
3. Copy the `request_id` (col B), paste into CW Logs Insights:
   ```
   fields @timestamp, action, terminatingRuleId
   | filter @message like /<request_id>/
   ```

---

## Test metadata

`test_metadata.csv` is checked into this folder. It maps each
`juiceshop-NNNN` test_id to:

| Column | Source |
|---|---|
| `test_id` | e.g. `juiceshop-0042` |
| `attack_family` | one of `xss`, `sqli`, `cmdi`, `lfi`, `rfi` (lower-case) |
| `payload` | the literal attack payload string |

When `build_comparison.py` runs, every RAW tab is joined against this
CSV to populate the `payload` and `attack_family` columns. Test_ids
absent from the CSV fall through as `Uncategorized` — they will still
appear in all the tables, just labelled accordingly.

The CSV was generated once from the old `old_managed.xlsx` artefact;
the script has **no runtime dependency** on anything in `~/Downloads/`.

---

## File layout

```
ml-training/
├── Makefile                  driver (use this, not the scripts directly)
├── README.md                 you are here
├── requirements.txt          openpyxl + boto3 (validate.py only)
├── test_metadata.csv         test_id -> attack_family + payload (309 rows)
├── validate.py               pytest report -> evidence JSON
├── build_xlsx.py             evidence JSON -> per-(policy, placement) XLSX
├── build_comparison.py       evidence JSONs -> consolidated comparison XLSX
├── mltest/                   venv (created by `make install`, gitignored)
├── runs/
│   ├── 20260521_run/         evidence JSONs for this run date
│   └── comparison_*.xlsx     generated workbooks
├── output/                   `make validate` output
└── _archive_20260520/        retired MCDA / scoring scripts (not in active path)
```

---

## Adding a new run date

```bash
mkdir -p runs/20260601_run
cp ~/Downloads/validate_baseline_*.json runs/20260601_run/
make comparison RUN_DATE=20260601
```

No code changes required — the date flows through every command via
`RUN_DATE`.
