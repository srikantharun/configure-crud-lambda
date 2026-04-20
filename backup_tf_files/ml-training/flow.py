"""
Prefect flow for WAF policy quality ML pipeline (local, no MLflow).

Usage:
    # Analyse a single policy version
    python flow.py --report-file ../reports/test_custom_v3.json

    # Analyse all reports in a directory
    python flow.py --reports-dir ../reports

    # Compare multiple policy versions
    python flow.py --compare ../reports/test_custom_v1.json ../reports/test_custom_v2.json ../reports/test_custom_v3.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
from prefect import flow, task, get_run_logger

from config import TrainingConfig, EvalConfig
from features import (
    build_features_from_report,
    build_features_from_reports,
    build_policy_summary,
    get_feature_columns,
    load_single_report,
)
from train import split_data, get_xy, train_all_models, get_feature_importance
from evaluate import evaluate_model, print_evaluation
from explain import explain_xgboost


# =========================================================================
# Prefect Tasks
# =========================================================================

@task(name="load-test-data")
def load_data(reports_dir: str = None, report_file: str = None) -> pd.DataFrame:
    """Load test results from local JSON files."""
    logger = get_run_logger()

    if report_file:
        logger.info(f"Loading: {report_file}")
        report = load_single_report(report_file)
        df = build_features_from_report(report)
        logger.info(f"Loaded {len(df)} test results")
        return df

    if reports_dir:
        logger.info(f"Loading all reports from {reports_dir}")
        df = build_features_from_reports(reports_dir)
        logger.info(f"Loaded {len(df)} test results")
        return df

    raise ValueError("Must specify --reports-dir or --report-file")


@task(name="build-policy-summary")
def build_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Build policy-level summary statistics."""
    logger = get_run_logger()
    summary = build_policy_summary(df)
    logger.info(f"Policy summary:\n{summary.to_string()}")
    return summary


@task(name="split-data")
def split_dataset(df: pd.DataFrame, config: TrainingConfig) -> tuple:
    """Split data into train/val/test."""
    logger = get_run_logger()

    if len(df) < 20:
        logger.warning(f"Only {len(df)} samples — using all data (no split)")
        return df, df, df

    train_df, val_df, test_df = split_data(df, config=config)
    return train_df, val_df, test_df


@task(name="train-models")
def train_models(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: list[str],
    config: TrainingConfig,
) -> dict:
    """Train XGBoost, GBM, and Logistic Regression."""
    return train_all_models(train_df, val_df, feature_cols, config=config)


@task(name="evaluate-models")
def evaluate_models(
    models: dict,
    test_df: pd.DataFrame,
    feature_cols: list[str],
    eval_config: EvalConfig,
) -> dict:
    """Evaluate all models on test set."""
    logger = get_run_logger()
    X_test, y_test = get_xy(test_df, feature_cols)

    all_metrics = {}
    for name, model in models.items():
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None

        metrics = evaluate_model(
            model_name=name,
            y_true=y_test,
            y_pred=y_pred,
            y_prob=y_prob,
            df=test_df,
            config=eval_config,
        )
        all_metrics[name] = metrics
        print_evaluation(name, metrics)

    best_name = max(all_metrics, key=lambda k: all_metrics[k]["waf_quality_score"])
    logger.info(f"Best model: {best_name} (score: {all_metrics[best_name]['waf_quality_score']})")

    return all_metrics


@task(name="generate-quality-report")
def generate_quality_report(
    all_metrics: dict,
    policy_summary: pd.DataFrame,
    feature_importances: dict,
    output_dir: str,
    policy_version: str = "",
) -> str:
    """Generate a JSON quality report."""
    logger = get_run_logger()

    best_model = max(all_metrics, key=lambda k: all_metrics[k]["waf_quality_score"])
    best_metrics = all_metrics[best_model]

    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "policy_version": policy_version,
        "quality_grade": _grade_policy(best_metrics),
        "best_model": best_model,
        "models": all_metrics,
        "feature_importances": {
            name: fi.head(10).to_dict(orient="records")
            for name, fi in feature_importances.items()
            if not fi.empty
        },
        "policy_summary": policy_summary.to_dict(orient="records") if not policy_summary.empty else [],
        "recommendations": _generate_recommendations(best_metrics, policy_summary),
    }

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"quality_{policy_version}.json" if policy_version else "waf_quality_report.json"
    output_path = str(Path(output_dir) / filename)

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    # Print summary to console
    print(f"\n{'=' * 60}")
    print(f"WAF POLICY QUALITY REPORT")
    print(f"{'=' * 60}")
    print(f"  Policy:       {policy_version}")
    print(f"  Grade:        {report['quality_grade']}")
    print(f"  Best Model:   {best_model}")
    print(f"  Quality Score: {best_metrics['waf_quality_score']}")
    print(f"  Evasion Rate: {best_metrics['evasion_rate']}")
    print(f"  F1 (weighted): {best_metrics['f1_weighted']}")
    print(f"\n  Recommendations:")
    for rec in report["recommendations"]:
        print(f"    - {rec}")
    print(f"\n  Saved to: {output_path}")
    print(f"{'=' * 60}")

    return output_path


@task(name="shap-explain")
def shap_explain(
    models: dict,
    test_df: pd.DataFrame,
    feature_cols: list[str],
    output_dir: str,
) -> dict:
    """Run SHAP explanation on XGBoost model."""
    logger = get_run_logger()

    if "xgboost" not in models:
        logger.warning("No XGBoost model found, skipping SHAP")
        return {}

    X_test = test_df[feature_cols].fillna(0).values
    logger.info(f"Running SHAP on {len(X_test)} test samples...")

    report = explain_xgboost(
        model=models["xgboost"],
        X_test=X_test,
        feature_cols=feature_cols,
        test_df=test_df,
        output_dir=output_dir,
    )

    # Print key insights
    for insight in report.get("insights", []):
        logger.info(f"  SHAP: {insight}")

    return report


@task(name="compare-policies")
def compare_policies(report_files: list[str], output_dir: str) -> str:
    """Compare multiple policy versions side by side."""
    logger = get_run_logger()

    comparisons = []

    for report_file in report_files:
        report = load_single_report(report_file)
        df = build_features_from_report(report)

        policy_name = report.get("summary", {}).get("policy", Path(report_file).stem)
        test_summary = report.get("summary", {})

        entry = {
            "policy_version": policy_name,
            "source_file": report_file,
            "total_tests": test_summary.get("total_requirements", len(df)),
            "passed": test_summary.get("passed", int(df["is_pass"].sum()) if not df.empty else 0),
            "failed": test_summary.get("failed", int((~df["is_pass"].astype(bool)).sum()) if not df.empty else 0),
            "pass_rate": test_summary.get("pass_rate", round(df["is_pass"].mean() * 100, 2) if not df.empty else 0),
            "block_rate": round(df["is_blocked"].mean() * 100, 2) if not df.empty else 0,
            "backend_crash_count": int(df["is_backend_crash"].sum()) if not df.empty else 0,
            "avg_duration_ms": round(df["duration_ms"].mean(), 1) if not df.empty else 0,
        }

        if not df.empty:
            for tt in df["tuning_type"].unique():
                subset = df[df["tuning_type"] == tt]
                entry[f"block_rate_{tt}"] = round(subset["is_blocked"].mean() * 100, 2)

        comparisons.append(entry)

    comparison_report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "policy_comparison",
        "policies": comparisons,
        "summary": _build_comparison_summary(comparisons),
    }

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_path = str(Path(output_dir) / "policy_comparison.json")
    with open(output_path, "w") as f:
        json.dump(comparison_report, f, indent=2)

    # Print table
    print(f"\n{'=' * 80}")
    print("POLICY VERSION COMPARISON")
    print(f"{'=' * 80}")
    print(f"{'Policy':<25} {'Pass%':>8} {'Block%':>8} {'Crashes':>8} {'Avg ms':>8}")
    print(f"{'-' * 80}")
    for p in comparisons:
        print(f"{p['policy_version']:<25} {p['pass_rate']:>7.1f}% {p['block_rate']:>7.1f}% {p['backend_crash_count']:>8} {p['avg_duration_ms']:>7.1f}")
    print(f"{'=' * 80}")

    best = comparison_report["summary"]
    print(f"\nBest: {best.get('best_policy', 'N/A')} ({best.get('best_pass_rate', 0)}%)")
    print(f"Saved to: {output_path}")

    return output_path


def _build_comparison_summary(comparisons: list[dict]) -> dict:
    if not comparisons:
        return {}
    best = max(comparisons, key=lambda c: c["pass_rate"])
    worst = min(comparisons, key=lambda c: c["pass_rate"])
    return {
        "best_policy": best["policy_version"],
        "best_pass_rate": best["pass_rate"],
        "worst_policy": worst["policy_version"],
        "worst_pass_rate": worst["pass_rate"],
        "total_policies_compared": len(comparisons),
    }


def _grade_policy(metrics: dict) -> str:
    score = metrics.get("waf_quality_score", 0)
    evasion = metrics.get("evasion_rate", 1)
    if score >= 1.8 and evasion <= 0.02:
        return "A"
    elif score >= 1.5 and evasion <= 0.05:
        return "B"
    elif score >= 1.0 and evasion <= 0.10:
        return "C"
    elif score >= 0.5:
        return "D"
    else:
        return "F"


def _generate_recommendations(metrics: dict, summary: pd.DataFrame) -> list[str]:
    recs = []

    evasion = metrics.get("evasion_rate", 0)
    if evasion > 0.05:
        recs.append(f"HIGH: Evasion rate is {evasion:.1%} — review WAF rules for bypassed attack categories")

    if metrics.get("false_positives", 0) > 0:
        fp = metrics["false_positives"]
        recs.append(f"MEDIUM: {fp} false positive(s) detected — review FP tuning for affected endpoints")

    for key, val in metrics.items():
        if key.startswith("coverage_") and val < 0.90:
            cat = key.replace("coverage_", "")
            recs.append(f"LOW: {cat} block rate is {val:.1%} — consider tightening {cat} detection rules")

    if not summary.empty and "backend_crash_rate" in summary.columns:
        crash_rate = summary["backend_crash_rate"].mean()
        if crash_rate > 0.01:
            recs.append(f"HIGH: Backend crash rate is {crash_rate:.1%} — payloads bypassing WAF and crashing backend")

    if not recs:
        recs.append("Policy looks healthy. No critical gaps detected.")

    return recs


# =========================================================================
# Prefect Flows
# =========================================================================

@flow(name="waf-ml-pipeline", log_prints=True)
def waf_ml_pipeline(
    reports_dir: str = None,
    report_file: str = None,
    output_dir: str = "output",
    policy_version: str = "",
):
    """
    WAF Policy Quality ML Pipeline.

    1. Load JSON test results
    2. Build features + policy summary
    3. Train XGBoost, GBM, Logistic Regression
    4. Evaluate on security KPIs
    5. Generate quality report with grade + recommendations
    """
    training_config = TrainingConfig()
    eval_config = EvalConfig()

    if not policy_version and report_file:
        policy_version = Path(report_file).stem

    # Load
    df = load_data(reports_dir=reports_dir, report_file=report_file)
    print(f"\nDataset: {len(df)} test results")

    # Summary
    policy_summary = build_summary(df)

    # Features
    feature_cols = get_feature_columns(df)
    print(f"Features ({len(feature_cols)}): {feature_cols}")

    # Split
    train_df, val_df, test_df = split_dataset(df, training_config)

    # Train
    models = train_models(train_df, val_df, feature_cols, training_config)

    # Evaluate
    all_metrics = evaluate_models(models, test_df, feature_cols, eval_config)

    # Feature importances
    feature_importances = {
        name: get_feature_importance(model, feature_cols)
        for name, model in models.items()
    }

    # SHAP explanation
    shap_report = shap_explain(models, test_df, feature_cols, output_dir)

    # Report
    report_path = generate_quality_report(
        all_metrics, policy_summary, feature_importances, output_dir, policy_version,
    )

    return report_path


@flow(name="waf-compare-policies", log_prints=True)
def waf_compare_pipeline(
    report_files: list[str],
    output_dir: str = "output",
):
    """Compare multiple policy versions from their JSON test reports."""
    print(f"\nComparing {len(report_files)} policy versions...")
    return compare_policies(report_files, output_dir)


# =========================================================================
# CLI
# =========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Policy Quality ML Pipeline")
    parser.add_argument("--reports-dir", help="Directory with JSON reports")
    parser.add_argument("--report-file", help="Single JSON report file")
    parser.add_argument("--compare", nargs="+", help="Compare multiple JSON reports")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--policy-version", default="", help="Policy version label")

    args = parser.parse_args()

    if args.compare:
        waf_compare_pipeline(report_files=args.compare, output_dir=args.output_dir)
    elif args.reports_dir or args.report_file:
        waf_ml_pipeline(
            reports_dir=args.reports_dir,
            report_file=args.report_file,
            output_dir=args.output_dir,
            policy_version=args.policy_version,
        )
    else:
        print("ERROR: Must specify --reports-dir, --report-file, or --compare")
        sys.exit(1)
