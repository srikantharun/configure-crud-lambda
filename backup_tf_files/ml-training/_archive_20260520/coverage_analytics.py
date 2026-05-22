"""
WAF coverage analytics — rule-coverage diff, FN clusterer, drift tracker.

Operates on a manifest of validate JSONs (one per test campaign) rather than
a single report. Output is a multi-tab xlsx with the four analytical primitives
that actually answer the weakness question:

  1. Coverage cube      — block-rate by (baseline, placement, attack-category)
  2. FN clusters        — unsupervised grouping of false-negative payloads
                          + a regex seed per cluster for rule-candidate work
  3. Drift events       — per test_id verdict-change across runs of the same
                          (baseline, placement) — managed-rule version drift
  4. Rule importance    — per terminating_rule_id, how many unique test_ids it
                          uniquely blocks. Ablation proxy: "what coverage do we
                          lose if AWS deprecates this rule?"

Usage:
  python coverage_analytics.py \
      --requirements ~/Downloads/waf_requirements_get.yaml \
      --manifest      manifest.yaml \
      --input-dir     ~/Downloads \
      --output        output/coverage_analytics.xlsx
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter

import pandas as pd
import yaml


# -------------------- ingest --------------------

def load_validate_json(path: pathlib.Path) -> dict:
    """Load validate JSON, repairing missing leading `{` from server-side truncation."""
    text = path.read_text()
    m = re.search(r'\{\s*\n?\s*"timestamp"', text)
    if m:
        text = text[m.start():]
    text = text.lstrip()
    if not text.startswith("{"):
        text = "{" + text
    if not text.rstrip().endswith("}"):
        text = text + "\n}"
    return json.loads(text)


def tid_norm(t: str) -> str:
    return t.split(":")[0] if t else t


def load_requirements(path: pathlib.Path) -> dict:
    cfg = yaml.safe_load(path.read_text())
    return {
        r["id"]: {
            "tuning": (r.get("tuning_type") or "").lower(),
            "payload": (r.get("test_config") or {}).get("test_payload", ""),
            "method": r.get("method", ""),
            "uri": r.get("uri", ""),
        }
        for r in cfg.get("requirements", [])
    }


def build_long_table(manifest: dict, requirements: dict, input_dir: pathlib.Path) -> pd.DataFrame:
    """Join all runs into one long table keyed (run_id, test_id)."""
    rows = []
    for run in manifest["runs"]:
        path = input_dir / run["file"]
        if not path.exists():
            print(f"WARN: missing {path}", file=sys.stderr)
            continue
        d = load_validate_json(path)
        run_ts = d.get("timestamp", "")
        for e in d.get("evidence", []):
            tid = tid_norm(e.get("test_id", ""))
            meta = requirements.get(tid, {})
            cf = e.get("cf_waf_log") or {}
            alb = e.get("alb_waf_log") or {}
            rows.append({
                "run_id": run["file"],
                "run_ts": run_ts,
                "baseline": str(run.get("baseline", "")),
                "placement": run.get("placement", ""),
                "cf_active": bool(run.get("cf_active", True)),
                "test_id": tid,
                "tuning": meta.get("tuning", ""),
                "payload": meta.get("payload", ""),
                "verdict": e.get("verdict", ""),
                "http_status": e.get("http_status", ""),
                "request_id": e.get("request_id", ""),
                "cf_rule": cf.get("terminating_rule_id", ""),
                "alb_rule": alb.get("terminating_rule_id", ""),
            })
    return pd.DataFrame(rows)


# -------------------- analysis --------------------

def is_block(v: str) -> bool:
    return v in ("CF_BLOCK", "CF_ALLOW_ALB_BLOCK")


def is_fn(v: str) -> bool:
    return isinstance(v, str) and v.startswith("CF_ALLOW_ALB_ALLOW")


def coverage_cube(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["blocked"] = df["verdict"].apply(is_block).astype(int)
    cube = df.pivot_table(
        index=["baseline", "placement"],
        columns="tuning",
        values="blocked",
        aggfunc="mean",
        fill_value=0,
    ) * 100
    cube = cube.round(1)
    totals = (df.groupby(["baseline", "placement"])["blocked"].mean() * 100).round(1)
    cube["__overall_block_pct"] = totals
    return cube.reset_index()


def suggest_regex_seed(payloads: list[str], ngram: int = 5) -> str:
    """Return the most common n-char substring appearing in >= 50% of payloads."""
    if len(payloads) < 2:
        return ""
    counts = Counter()
    for p in payloads:
        if len(p) < ngram:
            continue
        for i in range(len(p) - ngram + 1):
            counts[p[i:i + ngram]] += 1
    threshold = max(2, len(payloads) // 2)
    for sub, c in counts.most_common(50):
        if c >= threshold:
            return sub
    return ""


def cluster_fn_payloads(df: pd.DataFrame, n_clusters: int) -> pd.DataFrame:
    """Char-n-gram TF-IDF + agglomerative clustering of unique FN payloads."""
    fn = df[df["verdict"].apply(is_fn)].drop_duplicates(subset=["test_id"])
    fn = fn[fn["payload"].astype(bool)]
    if fn.empty:
        return pd.DataFrame()

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.cluster import AgglomerativeClustering
    except ImportError:
        print("WARN: scikit-learn missing; clustering skipped", file=sys.stderr)
        return pd.DataFrame()

    payloads = fn["payload"].tolist()
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2)
    X = vec.fit_transform(payloads)
    k = max(2, min(n_clusters, X.shape[0] // 3))
    cl = AgglomerativeClustering(n_clusters=k, metric="cosine", linkage="average")
    labels = cl.fit_predict(X.toarray())

    fn = fn.copy()
    fn["cluster"] = labels

    out_rows = []
    for cid, grp in fn.groupby("cluster"):
        examples = grp["payload"].head(5).tolist()
        tunings = grp["tuning"].value_counts().to_dict()
        out_rows.append({
            "cluster": int(cid),
            "size": len(grp),
            "unique_test_ids": grp["test_id"].nunique(),
            "tuning_mix": ", ".join(f"{k}={v}" for k, v in tunings.items()),
            "regex_seed_5gram": suggest_regex_seed(grp["payload"].tolist(), 5),
            "regex_seed_4gram": suggest_regex_seed(grp["payload"].tolist(), 4),
            "example_payloads": " | ".join(examples),
            "test_id_sample": " ".join(grp["test_id"].head(8).tolist()),
        })
    return pd.DataFrame(out_rows).sort_values("size", ascending=False).reset_index(drop=True)


def drift_events(df: pd.DataFrame) -> pd.DataFrame:
    """Per (baseline, placement, test_id), report sequential verdict-change events."""
    out = []
    for (baseline, placement, tid), grp in df.groupby(["baseline", "placement", "test_id"]):
        grp = grp.sort_values("run_ts")
        if grp["verdict"].nunique() <= 1:
            continue
        prev = grp.iloc[0]
        for _, r in grp.iloc[1:].iterrows():
            if r["verdict"] != prev["verdict"]:
                out.append({
                    "baseline": baseline,
                    "placement": placement,
                    "test_id": tid,
                    "from_ts": prev["run_ts"],
                    "from_verdict": prev["verdict"],
                    "to_ts": r["run_ts"],
                    "to_verdict": r["verdict"],
                    "cf_rule_to": r["cf_rule"],
                    "alb_rule_to": r["alb_rule"],
                })
                prev = r
    return pd.DataFrame(out)


def rule_importance(df: pd.DataFrame) -> pd.DataFrame:
    """For each terminating_rule_id, count unique test_ids it blocked across all runs."""
    blocked = df[df["verdict"].apply(is_block)].copy()
    cf = blocked[blocked["verdict"] == "CF_BLOCK"].groupby("cf_rule")["test_id"].nunique().reset_index()
    cf.columns = ["rule_id", "unique_test_ids_blocked"]
    cf["tier"] = "CF"
    alb = blocked[blocked["verdict"] == "CF_ALLOW_ALB_BLOCK"].groupby("alb_rule")["test_id"].nunique().reset_index()
    alb.columns = ["rule_id", "unique_test_ids_blocked"]
    alb["tier"] = "ALB"
    return pd.concat([cf, alb], ignore_index=True).sort_values("unique_test_ids_blocked", ascending=False)


# -------------------- output --------------------

def write_xlsx(out_path: pathlib.Path, cube, clusters, drift, rules, long_df):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(out_path, engine="openpyxl") as wr:
        cube.to_excel(wr,     sheet_name="Coverage cube",   index=False)
        clusters.to_excel(wr, sheet_name="FN clusters",     index=False)
        drift.to_excel(wr,    sheet_name="Drift events",    index=False)
        rules.to_excel(wr,    sheet_name="Rule importance", index=False)
        long_df.to_excel(wr,  sheet_name="Long table",      index=False)


# -------------------- CLI --------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requirements", required=True, help="waf_requirements yaml")
    ap.add_argument("--manifest",     required=True, help="run manifest yaml")
    ap.add_argument("--input-dir",    default=".",   help="dir containing validate JSONs")
    ap.add_argument("--output",       default="output/coverage_analytics.xlsx")
    ap.add_argument("--clusters",     type=int, default=12)
    args = ap.parse_args()

    requirements = load_requirements(pathlib.Path(args.requirements).expanduser())
    manifest = yaml.safe_load(pathlib.Path(args.manifest).expanduser().read_text())
    input_dir = pathlib.Path(args.input_dir).expanduser().resolve()

    long_df = build_long_table(manifest, requirements, input_dir)
    if long_df.empty:
        sys.exit("ERROR: no rows in long table — check manifest paths")

    print(f"Loaded {len(long_df)} rows from {long_df['run_id'].nunique()} runs")

    cube     = coverage_cube(long_df)
    clusters = cluster_fn_payloads(long_df, n_clusters=args.clusters)
    drift    = drift_events(long_df)
    rules    = rule_importance(long_df)

    out = pathlib.Path(args.output).expanduser()
    write_xlsx(out, cube, clusters, drift, rules, long_df)
    print(f"Saved {out}")

    print("\nCoverage cube:")
    print(cube.to_string(index=False))
    if not clusters.empty:
        print("\nTop FN clusters:")
        print(clusters[["cluster", "size", "unique_test_ids", "tuning_mix",
                        "regex_seed_5gram"]].head(12).to_string(index=False))
    if not drift.empty:
        print(f"\nDrift events found: {len(drift)} (first 5 below)")
        print(drift.head(5).to_string(index=False))
    if not rules.empty:
        print("\nTop blocking rules:")
        print(rules.head(10).to_string(index=False))


if __name__ == "__main__":
    main()
