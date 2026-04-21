"""
Simple WAF policy analytics — no ML, just clear facts.

Usage:
    python analyze.py --report-file ../reports/waf_rg_hsbc_custom_v3.json
    python analyze.py --compare ../reports/v1.json ../reports/v2.json ../reports/v3.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# Evasion technique classifiers
EVASION_PATTERNS = {
    "double_encoding": re.compile(r"%25[0-9a-fA-F]{2}"),
    "unicode_encoding": re.compile(r"%u[0-9a-fA-F]{4}"),
    "url_encoding": re.compile(r"%[0-9a-fA-F]{2}"),
    "base64": re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
    "html_comment_split": re.compile(r"<!--.*?-->", re.DOTALL),
    "nested_tags": re.compile(r"<scr.*ipt|scrscript", re.IGNORECASE),
    "null_byte": re.compile(r"%00|\\x00|\\0"),
    "case_mixing": re.compile(r"[a-z][A-Z]|[A-Z][a-z].*[A-Z]"),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e|%c0%af"),
    "ifs_bypass": re.compile(r"\$\{IFS\}"),
    "comment_obfuscation": re.compile(r"/\*.*?\*/|--\+"),
    "partial_encoding": re.compile(r"%[0-9a-f]{1}[a-z]|[a-z]%[0-9a-f]{2}[a-z]", re.IGNORECASE),
}


def load_report(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_requirements(yaml_path: str) -> dict:
    """Load waf_requirements.yaml and return {id: requirement} lookup."""
    import yaml
    with open(yaml_path) as f:
        data = yaml.safe_load(f)
    return {r["id"]: r for r in data.get("requirements", [])}


def detect_evasion_techniques(payload: str) -> list[str]:
    """Detect which evasion techniques a payload uses."""
    techniques = []
    for name, pattern in EVASION_PATTERNS.items():
        if pattern.search(payload):
            techniques.append(name)
    return techniques


def analyze_report(report: dict, requirements: dict = None) -> dict:
    """Analyze a single test report and produce clear findings."""
    results = report.get("results", [])
    summary = report.get("summary", {})
    req_meta = {m["requirement_id"]: m for m in report.get("requirements_metadata", [])}

    # Categorise results
    passed = [r for r in results if r["status"] == "pass"]
    failed = [r for r in results if r["status"] == "fail"]
    errors = [r for r in results if r["status"] == "error"]
    crashes = [r for r in results if r.get("actual_action") == "BACKEND_CRASH"]

    # Group by tuning type
    by_type = defaultdict(lambda: {"total": 0, "blocked": 0, "bypassed": 0, "crashed": 0})
    for r in results:
        meta = req_meta.get(r["requirement_id"], {})
        tt = meta.get("tuning_type", "unknown")
        by_type[tt]["total"] += 1
        if r["http_status"] == 403:
            by_type[tt]["blocked"] += 1
        elif r.get("actual_action") == "BACKEND_CRASH":
            by_type[tt]["crashed"] += 1
        else:
            by_type[tt]["bypassed"] += 1

    # Analyze failed payloads
    bypassed_payloads = []
    evasion_stats = defaultdict(int)

    for r in failed:
        req_id = r["requirement_id"]
        meta = req_meta.get(req_id, {})
        tt = meta.get("tuning_type", "unknown")

        # Get payload from requirements if available
        payload = ""
        if requirements and req_id in requirements:
            payload = requirements[req_id].get("test_config", {}).get("test_payload", "")

        techniques = detect_evasion_techniques(str(payload)) if payload else []
        for tech in techniques:
            evasion_stats[tech] += 1

        bypassed_payloads.append({
            "id": req_id,
            "category": tt,
            "http_status": r["http_status"],
            "payload": str(payload)[:100] if payload else "N/A",
            "evasion_techniques": techniques,
            "reason": r.get("actual_action", "unknown"),
        })

    # Build category summary
    category_summary = {}
    for tt, counts in sorted(by_type.items()):
        total = counts["total"]
        category_summary[tt] = {
            "total": total,
            "blocked": counts["blocked"],
            "bypassed": counts["bypassed"],
            "crashed": counts["crashed"],
            "block_rate": round(counts["blocked"] / total * 100, 1) if total > 0 else 0,
        }

    # Top evasion techniques
    evasion_ranking = sorted(evasion_stats.items(), key=lambda x: x[1], reverse=True)

    analysis = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "policy": summary.get("policy", "unknown"),
        "overview": {
            "total_tests": len(results),
            "blocked_by_waf": len(passed),
            "bypassed_waf": len(failed) - len(crashes),
            "backend_crashes": len(crashes),
            "errors": len(errors),
            "overall_block_rate": round(len(passed) / len(results) * 100, 1) if results else 0,
        },
        "category_breakdown": category_summary,
        "evasion_techniques_detected": dict(evasion_ranking),
        "bypassed_payloads": bypassed_payloads,
        "findings": _generate_findings(category_summary, evasion_ranking, crashes),
    }

    return analysis


def _generate_findings(category_summary: dict, evasion_ranking: list, crashes: list) -> list[str]:
    """Generate clear, actionable findings."""
    findings = []

    # Category gaps
    for cat, stats in category_summary.items():
        if stats["block_rate"] < 100 and stats["total"] > 0:
            gap = stats["bypassed"] + stats["crashed"]
            findings.append(
                f"{cat.upper()}: {stats['block_rate']}% block rate — "
                f"{gap}/{stats['total']} payloads bypassed WAF"
            )

    # Backend crashes
    total_crashes = sum(s["crashed"] for s in category_summary.values())
    if total_crashes > 0:
        crash_categories = [cat for cat, s in category_summary.items() if s["crashed"] > 0]
        findings.append(
            f"BACKEND CRASH: {total_crashes} payloads caused 502 — "
            f"categories: {', '.join(crash_categories)}"
        )

    # Evasion techniques
    if evasion_ranking:
        top_techniques = [f"{name} ({count})" for name, count in evasion_ranking[:5]]
        findings.append(f"TOP EVASION TECHNIQUES: {', '.join(top_techniques)}")

    # Missing rule groups
    missing_rules = []
    for cat in ["cmdi", "lfi", "rfi", "ssti"]:
        if cat in category_summary and category_summary[cat]["block_rate"] < 50:
            missing_rules.append(cat)
    if missing_rules:
        rule_map = {
            "cmdi": "AWSManagedRulesLinuxRuleSet",
            "lfi": "AWSManagedRulesLinuxRuleSet",
            "rfi": "AWSManagedRulesKnownBadInputsRuleSet",
            "ssti": "AWSManagedRulesKnownBadInputsRuleSet",
        }
        suggested = set(rule_map[c] for c in missing_rules)
        findings.append(
            f"MISSING WAF RULES: Add {', '.join(suggested)} to cover {', '.join(missing_rules)}"
        )

    if not findings:
        findings.append("ALL CLEAR: All attack categories fully blocked by WAF")

    return findings


def compare_reports(report_files: list[str]) -> dict:
    """Compare analytics across multiple policy versions."""
    comparisons = []

    for path in report_files:
        report = load_report(path)
        analysis = analyze_report(report)

        comparisons.append({
            "file": path,
            "policy": analysis["policy"],
            "total": analysis["overview"]["total_tests"],
            "blocked": analysis["overview"]["blocked_by_waf"],
            "bypassed": analysis["overview"]["bypassed_waf"],
            "crashes": analysis["overview"]["backend_crashes"],
            "block_rate": analysis["overview"]["overall_block_rate"],
            "categories": analysis["category_breakdown"],
        })

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": "comparison",
        "policies": comparisons,
    }


def print_analysis(analysis: dict):
    """Print analysis to console."""
    ov = analysis["overview"]

    print(f"\n{'=' * 70}")
    print(f"WAF POLICY ANALYSIS — {analysis['policy']}")
    print(f"{'=' * 70}")
    print(f"  Total tests:     {ov['total_tests']}")
    print(f"  Blocked by WAF:  {ov['blocked_by_waf']}")
    print(f"  Bypassed WAF:    {ov['bypassed_waf']}")
    print(f"  Backend crashes: {ov['backend_crashes']}")
    print(f"  Block rate:      {ov['overall_block_rate']}%")

    print(f"\n{'─' * 70}")
    print(f"{'Category':<12} {'Total':>6} {'Blocked':>8} {'Bypassed':>9} {'Crashed':>8} {'Rate':>7}")
    print(f"{'─' * 70}")
    for cat, stats in analysis["category_breakdown"].items():
        print(f"{cat:<12} {stats['total']:>6} {stats['blocked']:>8} {stats['bypassed']:>9} {stats['crashed']:>8} {stats['block_rate']:>6.1f}%")

    if analysis["evasion_techniques_detected"]:
        print(f"\n{'─' * 70}")
        print("EVASION TECHNIQUES (in bypassed payloads):")
        for tech, count in analysis["evasion_techniques_detected"].items():
            print(f"  {tech:<25} {count} payloads")

    print(f"\n{'─' * 70}")
    print("FINDINGS:")
    for i, finding in enumerate(analysis["findings"], 1):
        print(f"  {i}. {finding}")

    if analysis["bypassed_payloads"]:
        print(f"\n{'─' * 70}")
        print(f"BYPASSED PAYLOADS ({len(analysis['bypassed_payloads'])}):")
        for p in analysis["bypassed_payloads"]:
            techniques = ", ".join(p["evasion_techniques"]) if p["evasion_techniques"] else "none detected"
            print(f"  {p['id']:<20} [{p['category']:>6}] HTTP:{p['http_status']} evasion:[{techniques}]")
            if p["payload"] != "N/A":
                print(f"    payload: {p['payload']}")

    print(f"{'=' * 70}")


def print_comparison(comparison: dict):
    """Print comparison table."""
    print(f"\n{'=' * 80}")
    print("POLICY COMPARISON")
    print(f"{'=' * 80}")
    print(f"{'Policy':<20} {'Total':>6} {'Blocked':>8} {'Bypass':>8} {'Crash':>7} {'Rate':>7}")
    print(f"{'─' * 80}")
    for p in comparison["policies"]:
        print(f"{p['policy']:<20} {p['total']:>6} {p['blocked']:>8} {p['bypassed']:>8} {p['crashes']:>7} {p['block_rate']:>6.1f}%")

    # Per-category comparison
    all_cats = set()
    for p in comparison["policies"]:
        all_cats.update(p["categories"].keys())

    if all_cats:
        print(f"\n{'─' * 80}")
        print("BLOCK RATE BY CATEGORY:")
        header = f"{'Category':<12}" + "".join(f"{p['policy']:>15}" for p in comparison["policies"])
        print(header)
        print(f"{'─' * 80}")
        for cat in sorted(all_cats):
            row = f"{cat:<12}"
            for p in comparison["policies"]:
                rate = p["categories"].get(cat, {}).get("block_rate", 0)
                row += f"{rate:>14.1f}%"
            print(row)

    print(f"{'=' * 80}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Policy Analytics")
    parser.add_argument("--report-file", help="Single JSON report to analyze")
    parser.add_argument("--yaml-file", help="waf_requirements.yaml for payload details")
    parser.add_argument("--compare", nargs="+", help="Compare multiple reports")
    parser.add_argument("--output-dir", default="output", help="Output directory")

    args = parser.parse_args()

    if args.compare:
        comparison = compare_reports(args.compare)
        print_comparison(comparison)

        Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        out = f"{args.output_dir}/comparison.json"
        with open(out, "w") as f:
            json.dump(comparison, f, indent=2)
        print(f"\nSaved to {out}")

    elif args.report_file:
        report = load_report(args.report_file)
        requirements = {}
        if args.yaml_file:
            requirements = load_requirements(args.yaml_file)

        analysis = analyze_report(report, requirements)
        print_analysis(analysis)

        Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        out = f"{args.output_dir}/analysis.json"
        with open(out, "w") as f:
            json.dump(analysis, f, indent=2)
        print(f"\nSaved to {out}")

    else:
        print("Usage:")
        print("  python analyze.py --report-file ../reports/test.json")
        print("  python analyze.py --report-file ../reports/test.json --yaml-file ../modules/test_custom_v3/waf_requirements.yaml")
        print("  python analyze.py --compare ../reports/v1.json ../reports/v2.json")
        sys.exit(1)
