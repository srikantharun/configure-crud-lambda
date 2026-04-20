"""SHAP explanations for WAF policy quality models."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for EC2/headless
import matplotlib.pyplot as plt


def explain_xgboost(
    model,
    X_test: np.ndarray,
    feature_cols: list[str],
    test_df: pd.DataFrame,
    output_dir: str,
) -> dict:
    """
    Generate SHAP explanations for XGBoost model.

    Produces:
    - shap_summary.png      — which features matter most overall
    - shap_bar.png          — mean absolute SHAP per feature
    - shap_waterfall_*.png  — per-payload breakdown for failed tests
    - shap_report.json      — machine-readable SHAP values
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test)

    # 1. Summary plot — beeswarm showing all predictions
    plt.figure(figsize=(12, 8))
    shap.summary_plot(
        shap_values, X_test,
        feature_names=feature_cols,
        show=False,
        max_display=15,
    )
    plt.title("SHAP Summary — Feature Impact on WAF Block Prediction")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/shap_summary.png", dpi=150)
    plt.close()

    # 2. Bar plot — mean |SHAP| per feature
    plt.figure(figsize=(10, 6))
    shap.summary_plot(
        shap_values, X_test,
        feature_names=feature_cols,
        plot_type="bar",
        show=False,
        max_display=15,
    )
    plt.title("SHAP Feature Importance — Mean |SHAP Value|")
    plt.tight_layout()
    plt.savefig(f"{output_dir}/shap_bar.png", dpi=150)
    plt.close()

    # 3. Waterfall plots for interesting cases (failed/502 tests)
    waterfall_cases = _find_interesting_cases(test_df, shap_values)
    for i, case in enumerate(waterfall_cases[:5]):  # Max 5
        idx = case["index"]
        plt.figure(figsize=(10, 6))
        explanation = shap.Explanation(
            values=shap_values[idx],
            base_values=explainer.expected_value,
            data=X_test[idx],
            feature_names=feature_cols,
        )
        shap.waterfall_plot(explanation, show=False, max_display=12)
        plt.title(f"SHAP Waterfall — {case['test_id']} ({case['reason']})")
        plt.tight_layout()
        plt.savefig(f"{output_dir}/shap_waterfall_{i}_{case['test_id'].replace(':', '_')}.png", dpi=150)
        plt.close()

    # 4. Build machine-readable report
    report = _build_shap_report(shap_values, X_test, feature_cols, test_df, explainer)

    report_path = f"{output_dir}/shap_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nSHAP outputs saved to {output_dir}/")
    print(f"  - shap_summary.png       (which features matter)")
    print(f"  - shap_bar.png           (feature importance ranking)")
    print(f"  - shap_waterfall_*.png   (per-payload explanations)")
    print(f"  - shap_report.json       (machine-readable)")

    return report


def _find_interesting_cases(test_df: pd.DataFrame, shap_values: np.ndarray) -> list[dict]:
    """Find the most interesting cases to explain with waterfall plots."""
    cases = []

    for i, row in test_df.reset_index(drop=True).iterrows():
        if i >= len(shap_values):
            break

        # Backend crashes (502) — WAF gaps
        if row.get("is_backend_crash", 0) == 1:
            cases.append({
                "index": i,
                "test_id": row.get("test_id", f"test_{i}"),
                "reason": "backend_crash_502",
            })

        # Failed tests (not blocked when expected)
        elif row.get("is_pass", 1) == 0:
            cases.append({
                "index": i,
                "test_id": row.get("test_id", f"test_{i}"),
                "reason": "waf_bypass",
            })

    # If no failures, pick the most uncertain predictions (SHAP values close to 0)
    if not cases:
        uncertainty = np.abs(shap_values).sum(axis=1)
        most_uncertain = np.argsort(uncertainty)[:3]
        for idx in most_uncertain:
            if idx < len(test_df):
                row = test_df.iloc[idx]
                cases.append({
                    "index": int(idx),
                    "test_id": row.get("test_id", f"test_{idx}"),
                    "reason": "most_uncertain",
                })

    return cases


def _build_shap_report(
    shap_values: np.ndarray,
    X_test: np.ndarray,
    feature_cols: list[str],
    test_df: pd.DataFrame,
    explainer,
) -> dict:
    """Build a machine-readable SHAP report."""
    # Global feature importance (mean |SHAP|)
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    global_importance = sorted(
        [{"feature": f, "mean_abs_shap": round(float(v), 4)} for f, v in zip(feature_cols, mean_abs_shap)],
        key=lambda x: x["mean_abs_shap"],
        reverse=True,
    )

    # Top evasion drivers — features that push prediction toward "not blocked"
    # Negative SHAP = pushes toward class 0 (not blocked)
    mean_shap = shap_values.mean(axis=0)
    evasion_drivers = sorted(
        [{"feature": f, "mean_shap": round(float(v), 4)} for f, v in zip(feature_cols, mean_shap) if v < -0.01],
        key=lambda x: x["mean_shap"],
    )

    # Top blocking drivers — features that push toward "blocked"
    blocking_drivers = sorted(
        [{"feature": f, "mean_shap": round(float(v), 4)} for f, v in zip(feature_cols, mean_shap) if v > 0.01],
        key=lambda x: x["mean_shap"],
        reverse=True,
    )

    return {
        "base_value": round(float(explainer.expected_value), 4),
        "num_samples": len(X_test),
        "global_feature_importance": global_importance[:15],
        "evasion_drivers": evasion_drivers[:10],
        "blocking_drivers": blocking_drivers[:10],
        "insights": _generate_shap_insights(global_importance, evasion_drivers, blocking_drivers),
    }


def _generate_shap_insights(
    global_importance: list[dict],
    evasion_drivers: list[dict],
    blocking_drivers: list[dict],
) -> list[str]:
    """Generate human-readable insights from SHAP analysis."""
    insights = []

    # Top feature
    if global_importance:
        top = global_importance[0]
        insights.append(f"Most important feature: '{top['feature']}' (mean |SHAP| = {top['mean_abs_shap']})")

    # Evasion patterns
    evasion_features = [d["feature"] for d in evasion_drivers[:3]]
    if evasion_features:
        if any("encoding" in f for f in evasion_features):
            insights.append("Encoded payloads (URL/double/unicode encoding) are more likely to evade WAF detection")
        if any("nested" in f for f in evasion_features):
            insights.append("Nested/obfuscated tags (e.g., <scr<script>ipt>) reduce WAF detection probability")
        if any("length" in f for f in evasion_features):
            insights.append("Payload length affects detection — very short or very long payloads behave differently")
        if any("fp_label" in f for f in evasion_features):
            insights.append("False positive labels may be too broad — some real attacks are being allowed through FP exceptions")

    if not evasion_drivers:
        insights.append("No strong evasion patterns detected — WAF rules appear well-tuned")

    return insights
