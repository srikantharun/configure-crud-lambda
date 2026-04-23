"""
WAF Evidence Validation Report.

Queries BOTH CloudFront WAF and ALB WAF logs to produce
auditable evidence for every test case:

  Flow: Client -> CF WAF -> ALB WAF -> Juice Shop
                   |           |           |
            CF log group  ALB log group  502 = app crash

Evidence chain per test:
  - CF WAF log: BLOCK or ALLOW
  - If CF ALLOW -> ALB WAF log: BLOCK or ALLOW
  - If ALB ALLOW -> backend response (502 = crash)

Usage:
    python validate.py \
      --report-file ../reports/waf_rg_hsbc_custom_v3.json \
      --cf-log-group aws-waf-logs-baseline13 --cf-region us-east-1 \
      --alb-log-group aws-waf-logs-wpb-jenkins --alb-region eu-west-1 \
      --output-dir output
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import boto3


def query_waf_log(log_group: str, region: str, request_id: str, start_ms: int, end_ms: int) -> list:
    """Query a single CloudWatch WAF log group for a request ID."""
    client = boto3.client("logs", region_name=region)

    query = f"""
        fields @timestamp, action, terminatingRuleId, terminatingRuleType,
               httpRequest.uri, httpRequest.httpMethod, responseCodeSent, webaclId
        | filter @message like "{request_id}"
        | sort @timestamp asc
    """

    try:
        response = client.start_query(
            logGroupName=log_group,
            startTime=start_ms,
            endTime=end_ms,
            queryString=query,
            limit=10,
        )
        query_id = response["queryId"]

        for _ in range(30):
            result = client.get_query_results(queryId=query_id)
            if result["status"] == "Complete":
                entries = []
                for row in result["results"]:
                    entry = {}
                    for field in row:
                        entry[field["field"]] = field["value"]
                    entries.append(entry)
                return entries
            time.sleep(1)

        return []
    except Exception as e:
        return [{"error": str(e)}]


def validate_report(
    report_path: str,
    cf_log_group: str,
    cf_region: str,
    alb_log_group: str,
    alb_region: str,
    output_dir: str,
    sample_size: int = 0,
):
    """Validate every test result against both CF and ALB WAF logs."""

    with open(report_path) as f:
        report = json.load(f)

    results = report.get("results", [])
    timestamp = report.get("timestamp", "")

    # Time window for CloudWatch queries
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.utcnow() - timedelta(hours=2)

    start_ms = int((ts - timedelta(minutes=30)).timestamp() * 1000)
    end_ms = int((ts + timedelta(minutes=60)).timestamp() * 1000)

    # Select which results to validate
    if sample_size > 0:
        failures = [r for r in results if r["status"] == "fail"]
        passes = [r for r in results if r["status"] == "pass"]
        import random
        sample_passes = random.sample(passes, min(sample_size, len(passes)))
        results_to_validate = failures + sample_passes
        print(f"Validating {len(failures)} failures + {len(sample_passes)} sampled passes = {len(results_to_validate)} total")
    else:
        results_to_validate = results
        print(f"Validating all {len(results_to_validate)} results")

    print(f"CF WAF logs:  {cf_log_group} ({cf_region})")
    print(f"ALB WAF logs: {alb_log_group} ({alb_region})")
    print(f"Time window:  {ts - timedelta(minutes=30)} to {ts + timedelta(minutes=60)}")
    print()

    validated = []
    summary = {
        "total_validated": 0,
        "cf_block": 0,
        "cf_allow_alb_block": 0,
        "cf_allow_alb_allow": 0,
        "no_cf_log": 0,
        "no_alb_log": 0,
        "discrepancy": 0,
        "errors": 0,
    }

    for i, result in enumerate(results_to_validate):
        req_id = result.get("request_id", "")
        test_id = result.get("test_id", "")
        http_status = result.get("http_status", 0)

        print(f"  [{i+1}/{len(results_to_validate)}] {test_id} (HTTP:{http_status})", end="")

        if not req_id:
            print(" SKIP (no request ID)")
            continue

        # Step 1: Query CF WAF log
        cf_entries = query_waf_log(cf_log_group, cf_region, req_id, start_ms, end_ms)
        cf_entry = cf_entries[0] if cf_entries and "error" not in cf_entries[0] else None

        # Step 2: Query ALB WAF log
        alb_entries = query_waf_log(alb_log_group, alb_region, req_id, start_ms, end_ms)
        alb_entry = alb_entries[0] if alb_entries and "error" not in alb_entries[0] else None

        # Step 3: Determine verdict
        verdict, evidence = _determine_verdict(http_status, cf_entry, alb_entry)

        # Update summary
        summary["total_validated"] += 1
        if verdict == "CF_BLOCK":
            summary["cf_block"] += 1
        elif verdict == "CF_ALLOW_ALB_BLOCK":
            summary["cf_allow_alb_block"] += 1
        elif verdict == "CF_ALLOW_ALB_ALLOW_BACKEND_CRASH":
            summary["cf_allow_alb_allow"] += 1
        elif verdict == "NO_CF_LOG":
            summary["no_cf_log"] += 1
        elif verdict == "NO_ALB_LOG":
            summary["no_alb_log"] += 1
        elif "DISCREPANCY" in verdict:
            summary["discrepancy"] += 1
        elif verdict == "ERROR":
            summary["errors"] += 1

        print(f" -> {verdict}")

        entry = {
            "test_id": test_id,
            "requirement_id": result.get("requirement_id", ""),
            "request_id": req_id,
            "http_status": http_status,
            "pytest_status": result.get("status", ""),
            "verdict": verdict,
            "evidence": evidence,
            "cf_waf_log": _format_log_entry(cf_entry, "CloudFront WAF"),
            "alb_waf_log": _format_log_entry(alb_entry, "ALB WAF"),
        }
        validated.append(entry)

    # Build final report
    validation_report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_report": report_path,
        "cf_log_group": cf_log_group,
        "alb_log_group": alb_log_group,
        "summary": summary,
        "evidence": validated,
    }

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_path = f"{output_dir}/validation_evidence.json"
    with open(output_path, "w") as f:
        json.dump(validation_report, f, indent=2)

    _print_summary(summary, validated, output_path)

    return validation_report


def _determine_verdict(http_status: int, cf_entry: dict, alb_entry: dict) -> tuple:
    """Determine the validation verdict from both WAF logs."""

    cf_action = cf_entry.get("action", "") if cf_entry else None
    cf_rule = cf_entry.get("terminatingRuleId", "") if cf_entry else ""
    alb_action = alb_entry.get("action", "") if alb_entry else None
    alb_rule = alb_entry.get("terminatingRuleId", "") if alb_entry else ""

    # Case 1: No CF log at all
    if cf_entry is None:
        if http_status == 403:
            return "NO_CF_LOG", (
                f"HTTP 403 received but no CloudFront WAF log found. "
                f"The 403 may have come from CloudFront itself (not WAF). "
                f"ALB WAF: {'BLOCK (rule: ' + alb_rule + ')' if alb_action == 'BLOCK' else alb_action or 'no log'}."
            )
        return "NO_CF_LOG", f"No CloudFront WAF log found for this request."

    # Case 2: CF WAF BLOCK
    if cf_action == "BLOCK":
        if http_status == 403:
            return "CF_BLOCK", (
                f"CONFIRMED: CloudFront WAF blocked this request. "
                f"Rule: {cf_rule}. "
                f"Request never reached ALB."
            )
        else:
            return "DISCREPANCY_CF_BLOCK", (
                f"CloudFront WAF logged BLOCK but HTTP status was {http_status} (expected 403). "
                f"Rule: {cf_rule}."
            )

    # Case 3: CF WAF ALLOW -> check ALB
    if cf_action == "ALLOW":
        if alb_entry is None:
            if http_status == 502:
                return "CF_ALLOW_NO_ALB_LOG_502", (
                    f"CloudFront WAF allowed the request. "
                    f"No ALB WAF log found. "
                    f"502 may be from CloudFront origin connection failure OR backend crash."
                )
            return "NO_ALB_LOG", (
                f"CloudFront WAF allowed but no ALB WAF log found. "
                f"HTTP status: {http_status}."
            )

        if alb_action == "BLOCK":
            return "CF_ALLOW_ALB_BLOCK", (
                f"CONFIRMED: CloudFront WAF allowed, ALB WAF blocked. "
                f"CF passed inspection, ALB caught it. "
                f"ALB rule: {alb_rule}."
            )

        if alb_action == "ALLOW":
            if http_status == 502:
                return "CF_ALLOW_ALB_ALLOW_BACKEND_CRASH", (
                    f"CONFIRMED: Both WAFs allowed this payload. "
                    f"502 came from the backend (Juice Shop). "
                    f"This is a WAF coverage gap — neither WAF detected this payload."
                )
            return "CF_ALLOW_ALB_ALLOW", (
                f"Both WAFs allowed this request. HTTP status: {http_status}."
            )

    return "UNEXPECTED", f"Unexpected state: CF={cf_action}, ALB={alb_action}, HTTP={http_status}"


def _format_log_entry(entry: dict, source: str) -> dict:
    """Format a WAF log entry for the report."""
    if not entry:
        return {"source": source, "found": False}

    return {
        "source": source,
        "found": True,
        "action": entry.get("action", ""),
        "terminating_rule_id": entry.get("terminatingRuleId", ""),
        "terminating_rule_type": entry.get("terminatingRuleType", ""),
        "webacl_id": entry.get("webaclId", ""),
        "response_code_sent": entry.get("responseCodeSent", ""),
        "timestamp": entry.get("@timestamp", ""),
    }


def _print_summary(summary: dict, validated: list, output_path: str):
    """Print the validation summary."""
    print(f"\n{'=' * 70}")
    print("VALIDATION EVIDENCE SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total validated:              {summary['total_validated']}")
    print(f"")
    print(f"  CF WAF BLOCK (403):           {summary['cf_block']}")
    print(f"  CF ALLOW -> ALB BLOCK (403):  {summary['cf_allow_alb_block']}")
    print(f"  CF ALLOW -> ALB ALLOW (502):  {summary['cf_allow_alb_allow']}")
    print(f"")
    print(f"  No CF WAF log:                {summary['no_cf_log']}")
    print(f"  No ALB WAF log:               {summary['no_alb_log']}")
    print(f"  Discrepancies:                {summary['discrepancy']}")
    print(f"  Errors:                       {summary['errors']}")
    print(f"")

    # Effective block rate (with evidence)
    total = summary["total_validated"]
    confirmed_blocks = summary["cf_block"] + summary["cf_allow_alb_block"]
    confirmed_gaps = summary["cf_allow_alb_allow"]

    if total > 0:
        print(f"  CONFIRMED block rate:         {confirmed_blocks}/{total} ({confirmed_blocks/total*100:.1f}%)")
        print(f"  CONFIRMED WAF gaps:           {confirmed_gaps}/{total} ({confirmed_gaps/total*100:.1f}%)")

    print(f"\n  Evidence report: {output_path}")
    print(f"{'=' * 70}")

    # Print items needing review
    review_items = [v for v in validated if v["verdict"] not in ("CF_BLOCK", "CF_ALLOW_ALB_BLOCK")]
    if review_items:
        print(f"\nITEMS REQUIRING REVIEW ({len(review_items)}):")
        print(f"{'─' * 70}")
        print(f"{'Test ID':<30} {'HTTP':>5} {'Verdict':<35}")
        print(f"{'─' * 70}")
        for item in review_items:
            print(f"{item['test_id']:<30} {item['http_status']:>5} {item['verdict']}")
        print(f"{'─' * 70}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Evidence Validation Report")
    parser.add_argument("--report-file", required=True, help="Pytest JSON report")
    parser.add_argument("--cf-log-group", required=True, help="CloudFront WAF log group")
    parser.add_argument("--cf-region", default="us-east-1", help="CloudFront WAF region")
    parser.add_argument("--alb-log-group", required=True, help="ALB WAF log group")
    parser.add_argument("--alb-region", default="eu-west-1", help="ALB WAF region")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--sample", type=int, default=0,
                        help="Validate N random passes + all failures (0=validate all)")

    args = parser.parse_args()

    validate_report(
        report_path=args.report_file,
        cf_log_group=args.cf_log_group,
        cf_region=args.cf_region,
        alb_log_group=args.alb_log_group,
        alb_region=args.alb_region,
        output_dir=args.output_dir,
        sample_size=args.sample,
    )
