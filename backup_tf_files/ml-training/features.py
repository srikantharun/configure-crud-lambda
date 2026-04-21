"""Feature engineering from WAF test JSON reports."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd


# Payload pattern classifiers
PAYLOAD_PATTERNS = {
    "xss_script": re.compile(r"<script|</script|javascript:", re.IGNORECASE),
    "xss_event": re.compile(r"onerror|onload|onfocus|onmouseover", re.IGNORECASE),
    "xss_tag": re.compile(r"<img|<svg|<iframe|<math|<div", re.IGNORECASE),
    "sqli_union": re.compile(r"union\s+select|union\+select", re.IGNORECASE),
    "sqli_or": re.compile(r"'\s*or\s*'|'\s*OR\s*'|1'='1|1%27", re.IGNORECASE),
    "sqli_comment": re.compile(r"--|#|/\*", re.IGNORECASE),
    "sqli_function": re.compile(r"UTL_|CHR\(|CONCAT\(|VERSION\(|SLEEP\(", re.IGNORECASE),
    "lfi_traversal": re.compile(r"\.\./|\.\.\\|etc/passwd|etc/shadow", re.IGNORECASE),
    "rfi_remote": re.compile(r"http://|https://|ftp://", re.IGNORECASE),
    "ssti_template": re.compile(r"\$\{.*\}|\{\{.*\}\}|<%.*%>", re.IGNORECASE),
    "cmdi_shell": re.compile(r";\s*\w+|`\w+`|\|\||\&\&|/bin/", re.IGNORECASE),
    "log4j_jndi": re.compile(r"jndi:|ldap://|rmi://", re.IGNORECASE),
    "url_encoded": re.compile(r"%[0-9a-fA-F]{2}"),
    "double_encoded": re.compile(r"%25[0-9a-fA-F]{2}"),
    "unicode_encoded": re.compile(r"%u[0-9a-fA-F]{4}"),
    "html_entity": re.compile(r"&\w+;|&#\d+;|&#x[0-9a-f]+;", re.IGNORECASE),
    "nested_evasion": re.compile(r"<scr.*ipt|scrscript", re.IGNORECASE),
}


def load_json_reports(reports_dir: str) -> list[dict]:
    """Load all JSON test reports from a directory."""
    reports = []
    for json_file in Path(reports_dir).glob("*.json"):
        with open(json_file) as f:
            reports.append(json.load(f))
    return reports


def load_single_report(path: str) -> dict:
    """Load a single JSON report."""
    with open(path) as f:
        return json.load(f)


def extract_payload_features(payload: Optional[str]) -> dict:
    """Extract features from a test payload string."""
    if not payload:
        return {f"pat_{name}": 0 for name in PAYLOAD_PATTERNS} | {
            "payload_length": 0,
            "payload_entropy": 0.0,
            "special_char_ratio": 0.0,
            "encoding_depth": 0,
        }

    features = {}

    # Pattern match features (binary: does payload match this pattern?)
    for name, pattern in PAYLOAD_PATTERNS.items():
        features[f"pat_{name}"] = 1 if pattern.search(payload) else 0

    # Length features
    features["payload_length"] = len(payload)

    # Entropy (higher entropy = more randomised/encoded payload)
    if payload:
        prob = [payload.count(c) / len(payload) for c in set(payload)]
        features["payload_entropy"] = -sum(p * np.log2(p) for p in prob if p > 0)
    else:
        features["payload_entropy"] = 0.0

    # Special character ratio
    special = sum(1 for c in payload if not c.isalnum())
    features["special_char_ratio"] = special / len(payload) if payload else 0.0

    # Encoding depth (how many layers of encoding)
    depth = 0
    if features["pat_double_encoded"]:
        depth = 2
    elif features["pat_url_encoded"] or features["pat_unicode_encoded"]:
        depth = 1
    if features["pat_html_entity"]:
        depth = max(depth, 1)
    features["encoding_depth"] = depth

    return features


def classify_attack_category(payload: Optional[str], tuning_type: Optional[str]) -> str:
    """Classify a payload into an attack category."""
    if not payload:
        return "none"

    # Check patterns in priority order
    if PAYLOAD_PATTERNS["log4j_jndi"].search(payload):
        return "log4j"
    if PAYLOAD_PATTERNS["cmdi_shell"].search(payload):
        return "cmdi"
    if PAYLOAD_PATTERNS["lfi_traversal"].search(payload):
        return "lfi"
    if PAYLOAD_PATTERNS["rfi_remote"].search(payload) and not PAYLOAD_PATTERNS["xss_tag"].search(payload):
        return "rfi"
    if PAYLOAD_PATTERNS["ssti_template"].search(payload):
        return "ssti"
    if any(PAYLOAD_PATTERNS[p].search(payload) for p in ["sqli_union", "sqli_or", "sqli_comment", "sqli_function"]):
        return "sqli"
    if any(PAYLOAD_PATTERNS[p].search(payload) for p in ["xss_script", "xss_event", "xss_tag"]):
        return "xss"

    # Fall back to tuning_type
    if tuning_type in ("xss", "sqli", "size_body", "size_querystring"):
        return tuning_type

    return "unknown"


def build_features_from_report(report: dict) -> pd.DataFrame:
    """
    Build a feature DataFrame from a single JSON test report.

    Each row = one test result (one payload fired against WAF).
    """
    rows = []

    # Build a lookup of requirement metadata
    req_meta = {}
    for meta in report.get("requirements_metadata", []):
        req_meta[meta["requirement_id"]] = meta

    for result in report.get("results", []):
        req_id = result["requirement_id"]
        meta = req_meta.get(req_id, {})

        # Target: did WAF block the payload?
        # pass = WAF behaved as expected, fail = WAF gap
        is_blocked = 1 if result["http_status"] == 403 else 0
        is_pass = 1 if result["status"] == "pass" else 0
        is_backend_crash = 1 if result.get("actual_action") == "BACKEND_CRASH" else 0

        # Requirement-level features
        tuning_type = meta.get("tuning_type", "unknown")
        uri = meta.get("uri", "")
        method = meta.get("method", "GET")

        # Payload features (extract from test_id or metadata)
        # The payload itself isn't in the JSON result, so we derive from patterns
        payload = result.get("message", "")  # Best proxy we have

        # URI features
        uri_depth = uri.count("/") - 1  # path depth
        uri_length = len(uri)
        has_api_prefix = 1 if "/api/" in uri or "/rest/" in uri else 0

        # Build row
        row = {
            # Identifiers (not features, for tracking)
            "requirement_id": req_id,
            "test_id": result["test_id"],
            "policy_name": result["policy_name"],
            "timestamp": report.get("timestamp", ""),

            # Target variables
            "is_blocked": is_blocked,
            "is_pass": is_pass,
            "is_backend_crash": is_backend_crash,

            # Requirement features
            "tuning_type": tuning_type,
            "method": method,
            "uri_depth": uri_depth,
            "uri_length": uri_length,
            "has_api_prefix": has_api_prefix,
            "has_xss_fp_label": 1 if meta.get("has_xss_fp_label") else 0,
            "has_sqli_fp_label": 1 if meta.get("has_sqli_fp_label") else 0,
            "has_size_fp_label": 1 if meta.get("has_size_fp_label") else 0,
            "expected_action": result.get("expected_action", "BLOCK"),

            # Response features
            "http_status": result["http_status"],
            "duration_ms": result.get("duration_ms", 0),
            "has_actual_labels": 1 if result.get("actual_labels") else 0,
            "num_actual_labels": len(result.get("actual_labels", [])),
        }
        rows.append(row)

    df = pd.DataFrame(rows)

    # Encode categoricals
    if not df.empty:
        df["tuning_type_encoded"] = df["tuning_type"].astype("category").cat.codes
        df["method_encoded"] = df["method"].astype("category").cat.codes
        df["expected_block"] = (df["expected_action"] == "BLOCK").astype(int)

    return df


def build_features_from_reports(reports_dir: str) -> pd.DataFrame:
    """Load all JSON reports and build a combined feature DataFrame."""
    reports = load_json_reports(reports_dir)
    if not reports:
        raise ValueError(f"No JSON reports found in {reports_dir}")

    dfs = [build_features_from_report(r) for r in reports]
    combined = pd.concat(dfs, ignore_index=True)

    # Add run index (which test run this came from)
    run_idx = 0
    for df in dfs:
        combined.loc[combined["timestamp"] == df.iloc[0]["timestamp"] if not df.empty else "", "run_index"] = run_idx
        run_idx += 1

    return combined


def build_policy_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate per-policy summary statistics.

    One row per policy — used for policy-level quality scoring.
    """
    if df.empty:
        return pd.DataFrame()

    summary = df.groupby("policy_name").agg(
        total_tests=("test_id", "count"),
        total_blocked=("is_blocked", "sum"),
        total_passed=("is_pass", "sum"),
        total_backend_crash=("is_backend_crash", "sum"),
        block_rate=("is_blocked", "mean"),
        pass_rate=("is_pass", "mean"),
        backend_crash_rate=("is_backend_crash", "mean"),
        avg_duration_ms=("duration_ms", "mean"),
        max_duration_ms=("duration_ms", "max"),
        avg_labels=("num_actual_labels", "mean"),

        # Coverage by tuning type
        num_xss=("tuning_type", lambda x: (x == "xss").sum()),
        num_sqli=("tuning_type", lambda x: (x == "sqli").sum()),
        num_cmdi=("tuning_type", lambda x: (x == "cmdi").sum()),
        num_lfi=("tuning_type", lambda x: (x == "lfi").sum()),
        num_rfi=("tuning_type", lambda x: (x == "rfi").sum()),
        num_ssti=("tuning_type", lambda x: (x == "ssti").sum()),
        num_base64=("tuning_type", lambda x: (x == "base64").sum()),
        num_size_body=("tuning_type", lambda x: (x == "size_body").sum()),
    ).reset_index()

    # Block rate per tuning type
    for tt in ["xss", "sqli", "cmdi", "lfi", "rfi", "ssti", "base64", "size_body"]:
        subset = df[df["tuning_type"] == tt]
        if not subset.empty:
            rates = subset.groupby("policy_name")["is_blocked"].mean().reset_index()
            rates.columns = ["policy_name", f"block_rate_{tt}"]
            summary = summary.merge(rates, on="policy_name", how="left")
        else:
            summary[f"block_rate_{tt}"] = 0.0

    return summary


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    """Return the list of feature columns for model training."""
    exclude = {
        "requirement_id", "test_id", "policy_name", "timestamp",
        "is_blocked", "is_pass", "is_backend_crash",
        "tuning_type", "method", "expected_action", "run_index",
    }
    return [c for c in df.columns if c not in exclude]
