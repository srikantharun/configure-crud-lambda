#!/usr/bin/env python3
"""
Check which request_ids in the validate_baseline_*.json files did NOT get
a raw CloudWatch log written by pull_raw_cloudwatch.py.

For each request_id discovered in --evidence-dir, look for files named
<request_id>.cf.json and <request_id>.alb.json anywhere under --raw-dir,
and list the ones that are missing.

Usage:
    python3 check_missing_raw_logs.py \
        --evidence-dir ./ml-training/runs/20260601_run \
        --raw-dir      ~/Downloads/evidence/raw_logs \
        --out          ./missing_raw_logs.csv

Defaults match the pull_raw_cloudwatch.py defaults.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import sys
from collections import defaultdict


def load_json(path: pathlib.Path) -> dict | None:
    """Tolerate NBSP corruption from copy/paste."""
    try:
        text = path.read_text(encoding="utf-8").replace(" ", " ")
        return json.loads(text, strict=False)
    except Exception as e:
        print(f"WARN: failed to parse {path.name}: {e}", file=sys.stderr)
        return None


def discover_request_ids(evidence_dir: pathlib.Path):
    """Return {request_id: [source_file_basename, ...]}."""
    rids = defaultdict(list)
    for path in sorted(evidence_dir.glob("validate_baseline_*.json")):
        d = load_json(path)
        if not d:
            continue
        for rec in d.get("evidence", []):
            rid = rec.get("request_id")
            if rid and rid.startswith("waf-test-"):
                rids[rid].append(path.name)
    return dict(rids)


def discover_raw_files(raw_dir: pathlib.Path):
    """Return ({cf_present: set(request_ids)}, {alb_present: set(request_ids)})."""
    cf_present, alb_present = set(), set()
    if not raw_dir.exists():
        return cf_present, alb_present
    for p in raw_dir.rglob("waf-test-*.cf.json"):
        cf_present.add(p.name[:-len(".cf.json")])
    for p in raw_dir.rglob("waf-test-*.alb.json"):
        alb_present.add(p.name[:-len(".alb.json")])
    return cf_present, alb_present


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--evidence-dir", required=True,
                    help="dir containing validate_baseline_*.json (one run folder)")
    ap.add_argument("--raw-dir", default=str(pathlib.Path("~/Downloads/evidence/raw_logs").expanduser()),
                    help="dir tree containing the *.cf.json / *.alb.json files "
                         "(default: ~/Downloads/evidence/raw_logs)")
    ap.add_argument("--out", default="missing_raw_logs.csv",
                    help="CSV report of per-request_id status")
    args = ap.parse_args()

    evidence_dir = pathlib.Path(args.evidence_dir).expanduser().resolve()
    raw_dir      = pathlib.Path(args.raw_dir).expanduser().resolve()

    print(f"Evidence dir: {evidence_dir}")
    print(f"Raw-logs dir: {raw_dir}")
    print()

    if not evidence_dir.is_dir():
        sys.exit(f"ERROR: evidence dir not found: {evidence_dir}")

    rids = discover_request_ids(evidence_dir)
    if not rids:
        sys.exit("No request_ids found - check --evidence-dir")
    cf_present, alb_present = discover_raw_files(raw_dir)

    # --- per-source-file roll-up ----------------------------------------
    by_source = defaultdict(lambda: {"total": 0, "cf_missing": [], "alb_missing": []})
    for rid, sources in rids.items():
        cf_ok  = rid in cf_present
        alb_ok = rid in alb_present
        for src in sources:
            by_source[src]["total"] += 1
            if not cf_ok:  by_source[src]["cf_missing"].append(rid)
            if not alb_ok: by_source[src]["alb_missing"].append(rid)

    total = len(rids)
    missing_cf  = sum(1 for r in rids if r not in cf_present)
    missing_alb = sum(1 for r in rids if r not in alb_present)
    print(f"Distinct request_ids: {total}")
    print(f"  missing CF log:   {missing_cf:5d} ({100*missing_cf/total:.1f}%)")
    print(f"  missing ALB log:  {missing_alb:5d} ({100*missing_alb/total:.1f}%)")
    print()

    print(f"{'source file':45s} {'requests':>8s} {'no_cf':>8s} {'no_alb':>8s}")
    print("-" * 75)
    for src in sorted(by_source):
        s = by_source[src]
        print(f"{src:45s} {s['total']:>8d} {len(s['cf_missing']):>8d} {len(s['alb_missing']):>8d}")

    # --- write CSV ------------------------------------------------------
    out_path = pathlib.Path(args.out).expanduser().resolve()
    with out_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["request_id", "source_files", "cf_present", "alb_present", "missing_what"])
        for rid in sorted(rids):
            cf_ok = rid in cf_present
            alb_ok = rid in alb_present
            missing = []
            if not cf_ok:  missing.append("cf")
            if not alb_ok: missing.append("alb")
            w.writerow([
                rid,
                ";".join(rids[rid]),
                "yes" if cf_ok else "no",
                "yes" if alb_ok else "no",
                ",".join(missing) if missing else "",
            ])
    print()
    print(f"Per-request_id report: {out_path}")

    # --- exit code: 0 if nothing missing, 1 otherwise -------------------
    sys.exit(0 if (missing_cf == 0 and missing_alb == 0) else 1)


if __name__ == "__main__":
    main()
