#!/usr/bin/env python3
"""
REVISED: pulls raw CloudWatch WAF logs based on the request_id_mapping.csv
produced by the revised_*.sh scripts (NOT from validate_*.json any more).

Input:
  $EVIDENCE_DIR/request_id_mapping.csv (produced by revised_verify_*.sh)
  Columns: method_profile, test_id, tuning, request_id, http_status, timestamp_utc, response_file

For each (method_profile, request_id) it queries:
  - CloudFront WAF log group (default: aws-waf-logs-baseline13, region us-east-1)
  - ALB WAF log group       (default: aws-waf-logs-wpb-jenkins, region eu-west-1)

Output:
  $OUTPUT_DIR/raw_logs/<method_profile>/<request_id>.cf.json
  $OUTPUT_DIR/raw_logs/<method_profile>/<request_id>.alb.json
  $OUTPUT_DIR/raw_logs_index.csv

Time window: each row uses its OWN timestamp_utc as the anchor (+/- WINDOW_HOURS).
Tighter than the JSON-driven version -> fewer events scanned, faster, more reliable.

Usage:
  python3 revised_pull_raw_cloudwatch.py
  python3 revised_pull_raw_cloudwatch.py --profiles get_with_body --limit 5      # smoke
  python3 revised_pull_raw_cloudwatch.py --window-hours 24                       # widen window
  python3 revised_pull_raw_cloudwatch.py --mapping /path/to/request_id_mapping.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
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
DEFAULT_EVIDENCE_DIR = pathlib.Path(
    os.getenv("EVIDENCE_DIR", str(pathlib.Path("~/Downloads/evidence").expanduser()))
)
DEFAULT_MAPPING_FILE = pathlib.Path(
    os.getenv("MAPPING_FILE", str(DEFAULT_EVIDENCE_DIR / "request_id_mapping.csv"))
)
DEFAULT_OUTPUT_DIR = DEFAULT_EVIDENCE_DIR

# CloudFront WAF logs ALWAYS live in us-east-1 (CloudFront is global).
# ALB WAF logs live in the ALB's region.
CF_REGION  = os.getenv("WAF_CF_REGION",  "us-east-1")
ALB_REGION = os.getenv("WAF_ALB_REGION", os.getenv("AWS_REGION", "eu-west-1"))

CF_LOG_GROUP  = os.getenv("WAF_CF_LOG_GROUP",  "aws-waf-logs-baseline13")
ALB_LOG_GROUP = os.getenv("WAF_ALB_LOG_GROUP", "aws-waf-logs-wpb-jenkins")

DEFAULT_WINDOW_HOURS = 1   # +/- 1h around each row's timestamp_utc


# ---------------------------------------------------------------------------
def parse_iso_ts(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def row_window(row_ts, window_hours, fallback_hours=168):
    """Return (start_ms, end_ms). Tight window around row_ts; fallback if missing."""
    ts = parse_iso_ts(row_ts) if row_ts else None
    if ts is None:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=fallback_hours)
    else:
        start = ts - timedelta(hours=window_hours)
        end   = ts + timedelta(hours=window_hours)
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)


def pull_events(client, log_group, request_id, start_ms, end_ms):
    """filter_log_events for one request_id inside the time window. Paginates."""
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


def process_request(cf_client, alb_client, raw_dir, method_profile, request_id, start_ms, end_ms):
    out_dir = raw_dir / method_profile
    out_dir.mkdir(parents=True, exist_ok=True)
    cf_path  = out_dir / f"{request_id}.cf.json"
    alb_path = out_dir / f"{request_id}.alb.json"
    cf  = pull_events(cf_client,  CF_LOG_GROUP,  request_id, start_ms, end_ms)
    alb = pull_events(alb_client, ALB_LOG_GROUP, request_id, start_ms, end_ms)
    cf_path.write_text(json.dumps(cf, indent=2, default=str))
    alb_path.write_text(json.dumps(alb, indent=2, default=str))
    return {
        "method_profile": method_profile,
        "request_id": request_id,
        "cf_log_path": str(cf_path),
        "cf_event_count": len(cf),
        "alb_log_path": str(alb_path),
        "alb_event_count": len(alb),
    }


def load_mapping(path):
    if not path.exists():
        sys.exit(f"ERROR: mapping CSV not found: {path}\n"
                 f"Run the revised_*.sh scripts first to populate it.")
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mapping", default=str(DEFAULT_MAPPING_FILE),
                    help=f"path to request_id_mapping.csv (default: {DEFAULT_MAPPING_FILE})")
    ap.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                    help=f"directory to write raw_logs/ + raw_logs_index.csv (default: {DEFAULT_OUTPUT_DIR})")
    ap.add_argument("--profiles", default="",
                    help="comma-sep method_profiles to include (default: all in mapping)")
    ap.add_argument("--workers", type=int, default=8, help="parallel workers (default 8)")
    ap.add_argument("--limit", type=int, default=0, help="cap rows per profile (0 = all)")
    ap.add_argument("--window-hours", type=float, default=DEFAULT_WINDOW_HOURS,
                    help=f"+/- hours around each row's timestamp_utc (default {DEFAULT_WINDOW_HOURS})")
    ap.add_argument("--fallback-hours", type=float, default=168,
                    help="if a row has no timestamp_utc, use last N hours (default 168 = 7d)")
    args = ap.parse_args()

    mapping_path = pathlib.Path(args.mapping).expanduser().resolve()
    output_dir   = pathlib.Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw_logs"
    raw_dir.mkdir(parents=True, exist_ok=True)

    rows = load_mapping(mapping_path)
    profile_filter = {p.strip() for p in args.profiles.split(",") if p.strip()}
    if profile_filter:
        rows = [r for r in rows if r.get("method_profile") in profile_filter]

    if args.limit:
        from collections import defaultdict
        bucket = defaultdict(int)
        capped = []
        for r in rows:
            p = r.get("method_profile", "")
            if bucket[p] < args.limit:
                capped.append(r); bucket[p] += 1
        rows = capped

    profiles_in = sorted({r.get("method_profile", "") for r in rows})

    print(f"CF  region:    {CF_REGION}  (log group: {CF_LOG_GROUP})")
    print(f"ALB region:    {ALB_REGION}  (log group: {ALB_LOG_GROUP})")
    print(f"Mapping CSV:   {mapping_path}  ({len(rows)} rows after filters)")
    print(f"Output dir:    {output_dir}")
    print(f"Profiles:      {profiles_in}")
    print(f"Window:        +/- {args.window_hours}h around each row's timestamp_utc")
    print(f"Workers:       {args.workers}")
    print()

    if not rows:
        sys.exit("Nothing to do. Check --profiles / --limit / mapping CSV contents.")

    try:
        sts = boto3.client("sts", region_name=ALB_REGION).get_caller_identity()
        print(f"AWS account: {sts['Account']} / arn: {sts['Arn']}\n")
    except NoCredentialsError:
        sys.exit("ERROR: no AWS credentials. Run `aws configure` or export AWS_PROFILE.")

    cf_logs  = boto3.client("logs", region_name=CF_REGION)
    alb_logs = boto3.client("logs", region_name=ALB_REGION)

    INDEX_HEADERS = [
        "method_profile", "test_id", "tuning", "request_id",
        "http_status", "timestamp_utc",
        "cf_log_path", "cf_event_count",
        "alb_log_path", "alb_event_count",
        "response_file",
    ]

    rid_to_row = {r["request_id"]: r for r in rows}
    work = [(r["method_profile"], r["request_id"], r.get("timestamp_utc", "")) for r in rows]

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {}
        for profile, rid, ts in work:
            start_ms, end_ms = row_window(ts, args.window_hours, args.fallback_hours)
            futures[ex.submit(process_request, cf_logs, alb_logs, raw_dir,
                              profile, rid, start_ms, end_ms)] = rid
        for i, fut in enumerate(as_completed(futures), 1):
            results.append(fut.result())
            if i % 25 == 0 or i == len(futures):
                print(f"  {i}/{len(futures)} done")

    index_path = output_dir / "raw_logs_index.csv"
    with index_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(INDEX_HEADERS)
        for res in results:
            row = rid_to_row[res["request_id"]]
            w.writerow([
                res["method_profile"], row.get("test_id", ""), row.get("tuning", ""),
                res["request_id"],
                row.get("http_status", ""), row.get("timestamp_utc", ""),
                res["cf_log_path"], res["cf_event_count"],
                res["alb_log_path"], res["alb_event_count"],
                row.get("response_file", ""),
            ])

    print(f"\nwrote {index_path} ({len(results)} rows)")
    print(f"raw logs in {raw_dir}")
    cf_hits  = sum(1 for r in results if r["cf_event_count"]  > 0)
    alb_hits = sum(1 for r in results if r["alb_event_count"] > 0)
    print(f"hit summary: CF={cf_hits}/{len(results)}  ALB={alb_hits}/{len(results)}")
    print("\nNext step:")
    print(f"  aws s3 sync {output_dir} s3://<your-bucket>/baseline_1_3_evidence/")


if __name__ == "__main__":
    main()
