# WAF Policy Quality - ML Training Pipeline

## What This Does

Takes JSON test results from WAF testing (`make test-json`) and trains ML models to evaluate the quality of a WAF security policy. The pipeline answers:

- **How good is this policy at blocking attacks?**
- **Which attack categories are weak?**
- **Which payloads bypass WAF entirely?**
- **How does v1.3 compare to v1.1 and v1.2?**

---

## Quick Start

```bash
# 1. Generate test data
cd .. && make test-json MODULE=test_custom_v3

# 2. Install and train
cd ml-training
make install
make train-single REPORT=../reports/test_custom_v3.json

# 3. View results
cat output/quality_test_custom_v3.json
```

---

## Models Used

### 1. XGBoost (XGBClassifier)

XGBoost (Extreme Gradient Boosting) builds an ensemble of decision trees sequentially. Each new tree corrects the errors of the previous ones.

**How it works:**
- Starts with a base prediction (e.g., "50% chance WAF blocks this payload")
- Tree 1 looks at the errors — payloads that were misclassified — and learns patterns
- Tree 2 corrects what Tree 1 got wrong
- Repeats for N trees (default: 300)
- Final prediction = sum of all trees' contributions

**Why it's good for WAF analysis:**
- Handles mixed feature types well (categorical tuning_type + numeric duration_ms)
- Naturally captures interactions (e.g., "sqli payload + no FP label = likely blocked")
- Built-in regularisation (gamma, lambda) prevents overfitting on small datasets
- Feature importance tells you which features matter most for blocking decisions

**Key hyperparameters:**
| Parameter | Value | What it controls |
|-----------|-------|-----------------|
| n_estimators | 300 | Number of trees |
| max_depth | 6 | How complex each tree can be |
| learning_rate | 0.05 | How much each tree contributes (lower = more conservative) |
| subsample | 0.8 | Fraction of data each tree sees (prevents overfitting) |
| colsample_bytree | 0.8 | Fraction of features each tree uses |
| min_child_weight | 3 | Minimum samples to create a new branch |

### 2. Gradient Boosting (GradientBoostingClassifier)

Scikit-learn's implementation of gradient boosting. Same concept as XGBoost but a different implementation.

**How it differs from XGBoost:**
- XGBoost uses second-order gradients (Newton's method) — faster convergence
- XGBoost has built-in L1/L2 regularisation
- GBM from sklearn is simpler, slightly slower, but well-tested

**Why we include it:**
- Second opinion — if XGBoost and GBM disagree, the result is less certain
- More interpretable in some edge cases
- Serves as a cross-check on XGBoost's results

### 3. Logistic Regression (Baseline)

A simple linear model. If the data is straightforward (e.g., all XSS payloads get blocked), logistic regression will catch that with a single coefficient per feature.

**Why we include it:**
- Baseline — if logistic regression scores 95%, you don't need a complex model
- Fully interpretable: each coefficient directly shows feature impact
- If XGBoost scores 96% and logistic regression scores 95%, the problem is simple
- If XGBoost scores 96% and logistic regression scores 70%, the problem has non-linear patterns that matter

---

## Metrics Explained

### Primary: WAF Quality Score

```
score = (2.0 x malicious_block_rate) - (1.5 x false_positive_rate)
```

| Score | Grade | Meaning |
|-------|-------|---------|
| >= 1.8 | A | Excellent — blocks nearly all attacks, minimal FP |
| >= 1.5 | B | Good — some gaps but solid overall |
| >= 1.0 | C | Acceptable — noticeable gaps in coverage |
| >= 0.5 | D | Poor — significant attack categories bypassing WAF |
| < 0.5 | F | Critical — policy is not providing meaningful protection |

### Secondary Metrics

| Metric | What it measures | Target |
|--------|-----------------|--------|
| **Evasion Rate** | % of attacks that bypassed WAF | < 5% |
| **F1 (weighted)** | Balance of precision and recall | > 0.90 |
| **AUC-ROC** | Model's ability to distinguish blocked vs allowed | > 0.90 |
| **Coverage per category** | Block rate for xss, sqli, cmdi, etc. | > 90% each |
| **Backend Crash Rate** | % of payloads that caused 502 (WAF gap) | 0% |

### Confusion Matrix Terms

```
                    Predicted: Blocked    Predicted: Allowed
Actual: Blocked     True Positive (TP)    False Negative (FN) ← WAF gap!
Actual: Allowed     False Positive (FP)   True Negative (TN)
```

- **TP**: Attack correctly blocked by WAF (good)
- **FP**: Legitimate request incorrectly blocked (bad — breaks real users)
- **FN**: Attack that bypassed WAF (bad — security gap)
- **TN**: Legitimate request correctly allowed (good)

---

## SHAP (SHapley Additive exPlanations)

**Yes, SHAP is useful here.** It explains *why* the model made each prediction.

### What SHAP Tells You

Feature importance (from XGBoost) tells you *which features matter overall*. SHAP tells you *why a specific payload was predicted as blocked or allowed*.

Example without SHAP:
> "tuning_type is the most important feature" — ok, but how?

Example with SHAP:
> "juiceshop-0044 was predicted as 'not blocked' because:
> - tuning_type=sqli pushed prediction toward 'blocked' (+0.3)
> - but encoding_depth=2 pushed toward 'not blocked' (-0.5)
> - and payload_length=45 had minimal effect (+0.02)
> - Net: the double-encoding made WAF miss this SQLi payload"

### How SHAP Helps WAF Analysis

| Use Case | What SHAP Shows |
|----------|----------------|
| **Why did WAF miss this payload?** | Which payload features (encoding, length, pattern) caused the bypass |
| **Which evasion techniques work?** | If `encoding_depth` or `nested_evasion` consistently push toward "not blocked" |
| **Is a tuning rule too broad?** | If `has_xss_fp_label=1` strongly pushes toward "allowed" even for real attacks |
| **Compare policy versions** | SHAP values shift between v1.2 and v1.3 — shows what the policy update fixed |

### SHAP Summary Plot (what to look for)

```
Feature              Impact on "blocked" prediction
─────────────────────────────────────────────────
tuning_type_encoded  ████████████████  ← high impact, expected
has_sqli_fp_label    ██████████        ← FP labels reduce blocking (by design)
encoding_depth       ████████          ← encoded payloads harder to detect
payload_length       ██████            ← very long/short payloads behave differently
pat_nested_evasion   █████             ← nested tags bypass detection
special_char_ratio   ████              ← high special chars = likely attack
uri_depth            ██                ← minor effect
```

### Adding SHAP

Install: `pip install shap`

```python
import shap

# After training XGBoost
explainer = shap.TreeExplainer(models["xgboost"])
shap_values = explainer.shap_values(X_test)

# Summary plot (saved as image)
shap.summary_plot(shap_values, X_test, feature_names=feature_cols, show=False)
plt.savefig("output/shap_summary.png")

# Single prediction explanation (why did payload X bypass WAF?)
shap.force_plot(explainer.expected_value, shap_values[0], X_test[0], feature_names=feature_cols)
```

SHAP is not included in the pipeline by default to keep it simple. Add it when you want to investigate *why* specific payloads are bypassing WAF.

---

## Pipeline Architecture

```
reports/test_custom_v3.json
        │
        ▼
   ┌─────────┐
   │  Load    │  Parse JSON, extract test results
   └────┬─────┘
        ▼
   ┌──────────┐
   │ Features │  Build: tuning_type, uri_depth, http_status, duration_ms, etc.
   └────┬─────┘
        ▼
   ┌──────────┐
   │  Split   │  70% train / 15% val / 15% test
   └────┬─────┘
        ▼
   ┌──────────┐
   │  Train   │  XGBoost + GBM + Logistic Regression
   └────┬─────┘
        ▼
   ┌──────────┐
   │ Evaluate │  WAF quality score, evasion rate, coverage, F1, AUC
   └────┬─────┘
        ▼
   ┌──────────┐
   │  Report  │  output/quality_test_custom_v3.json
   └──────────┘
```

---

## File Structure

```
ml-training/
├── Makefile           make train, train-single, compare
├── requirements.txt   Python dependencies
├── config.py          Hyperparameters and eval thresholds
├── features.py        JSON → feature DataFrame
├── train.py           Model training (XGBoost, GBM, LR)
├── evaluate.py        WAF quality score, evasion rate, coverage
├── flow.py            Prefect flow orchestrating everything
└── output/            Generated reports
```

---

## Comparing Policy Versions

After running tests for each version:

```bash
make compare FILES='../reports/test_custom_v1.json ../reports/test_custom_v2.json ../reports/test_custom_v3.json'
```

Output:

```
================================================================================
POLICY VERSION COMPARISON
================================================================================
Policy                     Pass%   Block%  Crashes   Avg ms
--------------------------------------------------------------------------------
test_custom_v1              91.2%    89.5%       12     145.3
test_custom_v2              95.6%    94.1%        5     132.7
test_custom_v3              98.8%    97.4%        2     128.1
================================================================================

Best: test_custom_v3 (98.8%)
```

This shows policy v1.3 has fewer backend crashes and higher block rate — the WAF rules are improving.
