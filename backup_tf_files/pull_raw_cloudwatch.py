#!/usr/bin/env python3
"""
Pull raw CloudWatch WAF log events for every request_id in the validate JSONs.

For each (run_profile, request_id) it queries:
  - CloudFront WAF log group (default: aws-waf-logs-baseline13)
  - ALB WAF log group       (default: aws-waf-logs-wpb-jenkins)

Writes one JSON file per (request_id, log_group):
  evidence/raw_logs/<run_profile>/<request_id>.cf.json
  evidence/raw_logs/<run_profile>/<request_id>.alb.json

Plus an updated index CSV that points to each file.

Usage:
  cd ~/Downloads/evidence
  python3 pull_raw_cloudwatch.py [--profiles post_run1,get_with_body] [--workers 8]

After:
  aws s3 sync ~/Downloads/evidence s3://<your-bucket>/baseline_1_3_evidence/
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    sys.exit("ERROR: boto3 not installed. Run: pip install boto3")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_INPUT_DIR  = pathlib.Path(os.getenv("EVIDENCE_INPUT_DIR",  str(pathlib.Path("~/Downloads").expanduser())))
DEFAULT_OUTPUT_DIR = pathlib.Path(os.getenv("EVIDENCE_OUTPUT_DIR", str(pathlib.Path("~/Downloads/evidence").expanduser())))
REGION             = os.getenv("AWS_REGION", "eu-west-1")

CF_LOG_GROUP  = os.getenv("WAF_CF_LOG_GROUP",  "aws-waf-logs-baseline13")
ALB_LOG_GROUP = os.getenv("WAF_ALB_LOG_GROUP", "aws-waf-logs-wpb-jenkins")

# Time window around each run's validate.json timestamp
LOOKBACK_HOURS = 4
LOOKAHEAD_HOURS = 1

# (run_profile, source_json)
SOURCES = [
    ("post_run1",       "validate_log_baseline13.json"),
    ("post_run2",       "validate_log_baseline13-POST.json"),
    ("get_querystring", "validate_log_baseline13_get.json"),
    ("get_with_body",   "validate_evidence_get_with_body.json"),
]

# ---------------------------------------------------------------------------
def load_json_with_repair(path: pathlib.Path) -> dict:
    text = path.read_text()
    m = re.search(r'\{\s*\n?\s*"timestamp"', text)
    if m: text = text[m.start():]
    text = text.lstrip()
    if not text.startswith('{'): text = '{' + text
    if not text.rstrip().endswith('}'): text = text + '\n}'
    return json.loads(text)


def parse_run_window(top_ts: str | None) -> tuple[int, int]:
    """Return (start_ms, end_ms) for filter_log_events."""
    if top_ts:
        try:
            ts = datetime.fromisoformat(top_ts.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)
    start = ts - timedelta(hours=LOOKBACK_HOURS)
    end   = ts + timedelta(hours=LOOKAHEAD_HOURS)
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


def pull_events(client, log_group: str, request_id: str,
                start_ms: int, end_ms: int) -> list[dict]:
    """filter_log_events for a single request_id inside the time window."""
    events = []
    next_token = None
    pattern = f'"{request_id}"'
    while True:
        kwargs = dict(
            logGroupName=log_group,
            startTime=start_ms,
            endTime=end_ms,
            filterPattern=pattern,
            limit=100,
        )
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = client.filter_log_events(**kwargs)
        except ClientError as e:
            return [{"_error": str(e), "_log_group": log_group, "_request_id": request_id}]
        for ev in resp.get("events", []):
            try:
                ev["_parsed_message"] = json.loads(ev["message"])
            except (json.JSONDecodeError, TypeError):
                pass
            events.append(ev)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return events


def process_request(client, raw_dir: pathlib.Path, run_profile: str, request_id: str,
                    start_ms: int, end_ms: int) -> dict:
    out_dir = raw_dir / run_profile
    out_dir.mkdir(parents=True, exist_ok=True)
    cf_path  = out_dir / f"{request_id}.cf.json"
    alb_path = out_dir / f"{request_id}.alb.json"
    cf  = pull_events(client, CF_LOG_GROUP,  request_id, start_ms, end_ms)
    alb = pull_events(client, ALB_LOG_GROUP, request_id, start_ms, end_ms)
    cf_path.write_text(json.dumps(cf, indent=2, default=str))
    alb_path.write_text(json.dumps(alb, indent=2, default=str))
    return {
        "run_profile": run_profile,
        "request_id": request_id,
        "cf_log_path": str(cf_path),
        "cf_event_count": len(cf),
        "alb_log_path": str(alb_path),
        "alb_event_count": len(alb),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profiles", default=",".join(s[0] for s in SOURCES),
                    help="comma-sep list of run_profiles to pull (default: all 4)")
    ap.add_argument("--workers", type=int, default=8, help="parallel workers (default 8)")
    ap.add_argument("--limit", type=int, default=0, help="cap rows per profile (0 = all)")
    ap.add_argument("--verdicts", default="",
                    help="comma-sep verdicts to include (e.g. CF_ALLOW_ALB_ALLOW,NO_CF_LOG). "
                         "Empty = all verdicts.")
    ap.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR),
                    help="directory containing the validate_*.json files "
                         f"(default: {DEFAULT_INPUT_DIR}; env: EVIDENCE_INPUT_DIR)")
    ap.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                    help="directory to write raw_logs/ + raw_logs_index.csv "
                         f"(default: {DEFAULT_OUTPUT_DIR}; env: EVIDENCE_OUTPUT_DIR)")
    args = ap.parse_args()

    input_dir  = pathlib.Path(args.input_dir).expanduser().resolve()
    output_dir = pathlib.Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw_logs"
    raw_dir.mkdir(parents=True, exist_ok=True)

    selected = set(args.profiles.split(","))
    verdict_filter = {v.strip() for v in args.verdicts.split(",") if v.strip()}
    print(f"Region:        {REGION}")
    print(f"CF log group:  {CF_LOG_GROUP}")
    print(f"ALB log group: {ALB_LOG_GROUP}")
    print(f"Input dir:     {input_dir}")
    print(f"Output dir:    {output_dir}")
    print(f"Profiles:      {sorted(selected)}")
    if verdict_filter:
        print(f"Verdicts:      {sorted(verdict_filter)}")
    print(f"Workers:       {args.workers}")
    print()

    # Verify creds
    try:
        sts = boto3.client("sts", region_name=REGION).get_caller_identity()
        print(f"AWS account: {sts['Account']} / arn: {sts['Arn']}\n")
    except NoCredentialsError:
        sys.exit("ERROR: no AWS credentials. Run `aws configure` or export AWS_PROFILE.")

    logs = boto3.client("logs", region_name=REGION)

    index_path = output_dir / "raw_logs_index.csv"
    index_rows = [["run_profile", "request_id", "test_id", "verdict",
                   "http_status", "cf_log_path", "cf_event_count",
                   "alb_log_path", "alb_event_count"]]

    total_pulled = 0
    for run_profile, jname in SOURCES:
        if run_profile not in selected: continue
        src = input_dir / jname
        if not src.exists():
            print(f"SKIP {run_profile}: {jname} not found"); continue
        data = load_json_with_repair(src)
        start_ms, end_ms = parse_run_window(data.get("timestamp"))
        evs = data.get("evidence", [])
        if verdict_filter:
            before = len(evs)
            evs = [e for e in evs if e.get("verdict") in verdict_filter]
            print(f"  verdict filter {sorted(verdict_filter)}: {before} → {len(evs)} rows")
        if args.limit:
            evs = evs[:args.limit]
        rid_to_meta = {e.get("request_id"): e for e in evs if e.get("request_id")}
        rids = list(rid_to_meta.keys())
        print(f"\n=== {run_profile} ({len(rids)} request_ids, window: "
              f"{datetime.fromtimestamp(start_ms/1000, tz=timezone.utc).isoformat()} → "
              f"{datetime.fromtimestamp(end_ms/1000, tz=timezone.utc).isoformat()}) ===")

        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(process_request, logs, raw_dir, run_profile, rid,
                                 start_ms, end_ms): rid for rid in rids}
            for i, fut in enumerate(as_completed(futures), 1):
                res = fut.result()
                results.append(res)
                if i % 25 == 0 or i == len(rids):
                    print(f"  {i}/{len(rids)} done")

        for res in results:
            meta = rid_to_meta[res["request_id"]]
            index_rows.append([
                run_profile, res["request_id"], meta.get("test_id",""),
                meta.get("verdict",""), meta.get("http_status",""),
                res["cf_log_path"], res["cf_event_count"],
                res["alb_log_path"], res["alb_event_count"],
            ])
        total_pulled += len(results)

    with index_path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f, quoting=csv.QUOTE_ALL).writerows(index_rows)
    print(f"\nwrote {index_path} ({len(index_rows)-1} rows)")
    print(f"raw logs in {raw_dir}")
    print(f"total request_ids processed: {total_pulled}")
    print("\nNext step:")
    print(f"  aws s3 sync {output_dir} s3://<your-bucket>/baseline_1_3_evidence/")


if __name__ == "__main__":
    main()
