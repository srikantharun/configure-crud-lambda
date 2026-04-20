"""Evaluation metrics for WAF policy quality models."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

from config import EvalConfig


def waf_quality_score(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    config: EvalConfig = EvalConfig(),
) -> float:
    """
    Custom WAF policy quality score.

    Score = (weighted block rate for malicious) - (penalty for false positives)

    Higher is better. Max = malicious_block_weight (all attacks blocked, no FP).
    """
    # True positives: malicious correctly blocked
    tp = np.sum((y_true == 1) & (y_pred == 1))
    # False positives: legit incorrectly blocked
    fp = np.sum((y_true == 0) & (y_pred == 1))
    # False negatives: malicious not blocked (WAF gap)
    fn = np.sum((y_true == 1) & (y_pred == 0))
    # True negatives: legit correctly allowed
    tn = np.sum((y_true == 0) & (y_pred == 0))

    total_malicious = tp + fn
    total_legit = fp + tn

    block_rate = tp / total_malicious if total_malicious > 0 else 1.0
    fp_rate = fp / total_legit if total_legit > 0 else 0.0

    score = (config.malicious_block_weight * block_rate) - (config.false_positive_penalty * fp_rate)
    return round(score, 4)


def evasion_rate(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """
    Evasion rate: fraction of malicious payloads that bypassed WAF.

    Lower is better. 0.0 = no evasion.
    """
    malicious_mask = y_true == 1
    if malicious_mask.sum() == 0:
        return 0.0
    evaded = np.sum((y_true == 1) & (y_pred == 0))
    return round(evaded / malicious_mask.sum(), 4)


def coverage_by_category(
    df: pd.DataFrame,
    y_pred: np.ndarray,
    category_col: str = "tuning_type",
) -> dict:
    """
    Block rate per attack category.

    Returns dict of {category: block_rate}.
    """
    df = df.copy()
    df["predicted_blocked"] = y_pred

    coverage = {}
    for cat in df[category_col].unique():
        subset = df[df[category_col] == cat]
        if len(subset) > 0:
            coverage[cat] = round(subset["predicted_blocked"].mean(), 4)

    return coverage


def evaluate_model(
    model_name: str,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray = None,
    df: pd.DataFrame = None,
    config: EvalConfig = EvalConfig(),
) -> dict:
    """
    Full evaluation of a WAF quality model.

    Returns dict of all metrics for MLflow logging.
    """
    metrics = {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "f1_weighted": round(f1_score(y_true, y_pred, average="weighted", zero_division=0), 4),
        "waf_quality_score": waf_quality_score(y_true, y_pred, config),
        "evasion_rate": evasion_rate(y_true, y_pred),
    }

    # AUC if probabilities available
    if y_prob is not None and len(np.unique(y_true)) > 1:
        metrics["auc_roc"] = round(roc_auc_score(y_true, y_prob), 4)

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        metrics["true_positives"] = int(cm[1, 1])
        metrics["false_positives"] = int(cm[0, 1])
        metrics["true_negatives"] = int(cm[0, 0])
        metrics["false_negatives"] = int(cm[1, 0])

    # Coverage by attack category
    if df is not None and "tuning_type" in df.columns:
        coverage = coverage_by_category(df, y_pred)
        for cat, rate in coverage.items():
            metrics[f"coverage_{cat}"] = rate

    return metrics


def print_evaluation(model_name: str, metrics: dict):
    """Print evaluation results."""
    print(f"\n{'=' * 60}")
    print(f"MODEL: {model_name}")
    print(f"{'=' * 60}")
    print(f"  Accuracy:          {metrics['accuracy']}")
    print(f"  Precision:         {metrics['precision']}")
    print(f"  Recall:            {metrics['recall']}")
    print(f"  F1:                {metrics['f1']}")
    print(f"  F1 (weighted):     {metrics['f1_weighted']}")
    print(f"  WAF Quality Score: {metrics['waf_quality_score']}")
    print(f"  Evasion Rate:      {metrics['evasion_rate']}")
    if "auc_roc" in metrics:
        print(f"  AUC-ROC:           {metrics['auc_roc']}")
    print(f"  TP/FP/TN/FN:       {metrics.get('true_positives', '-')}/{metrics.get('false_positives', '-')}/{metrics.get('true_negatives', '-')}/{metrics.get('false_negatives', '-')}")

    # Coverage
    coverage_keys = [k for k in metrics if k.startswith("coverage_")]
    if coverage_keys:
        print(f"\n  Coverage by category:")
        for k in sorted(coverage_keys):
            cat = k.replace("coverage_", "")
            print(f"    {cat:20s} {metrics[k]:.2%}")
    print(f"{'=' * 60}")
