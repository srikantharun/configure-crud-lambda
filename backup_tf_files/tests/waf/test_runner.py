"""
WAF Test Runner - Executes test cases and generates coverage reports.

Test Cases:
1. POSITIVE: Fire payload and verify WAF blocks with 403

Note on CloudFront bug:
- For GET requests with large query strings, CloudFront blocks BEFORE WAF evaluates
- Workaround: Lower WAF query_string size rule from 1024 to 10 for testing
- This ensures WAF blocks (not CloudFront) so we can verify labels
"""
from __future__ import annotations

import json
import os
import time
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlparse

from .models import (
    WAFTestConfig,
    WAFRequirement,
    TestResult,
    TestStatus,
    CoverageReport,
    CheckType,
)
from .http_client import WAFHttpClient, WAFRequest
from .cloudwatch_client import CloudWatchWAFClient


class WAFTestRunner:
    """
    Test runner for WAF policy verification.

    Key behaviors:
    - Host header derived from WAF_ENDPOINT (not from yaml)
    - Only runs TEST 1 (positive) per requirement
    - Retries on 502 errors
    """

    MAX_HEADER_SIZE_BYTES = 8 * 1024  # 8KB
    NEGATIVE_URI_BODY_SIZE = 68000  # more than 64KB for negative uri body size
    NEGATIVE_URI_PREFIX = "/mytest"  # Configurable prefix for negative tests

    def __init__(
        self,
        waf_endpoint: str,
        cloudwatch_log_group: str,
        aws_region: str = "eu-west-1",
        account_id: str = "",
        owasp_namespace: str = "owasp",
        modules_root: Optional[Path] = None,
        negative_uri_prefix: str = "/mytest",
    ):
        self.waf_endpoint = waf_endpoint
        self.cloudwatch_log_group = cloudwatch_log_group
        self.account_id = account_id
        self.owasp_namespace = owasp_namespace
        self.negative_uri_prefix = negative_uri_prefix

        # Extract host from WAF_ENDPOINT for all requests
        parsed = urlparse(waf_endpoint)
        self.waf_host = parsed.netloc or parsed.path.split('/')[0]

        # Default modules root
        self.modules_root = modules_root or Path(__file__).parent.parent.parent / "modules" / "custom"

        # Initialize clients
        self.http = WAFHttpClient(base_url=waf_endpoint)
        self.cw = CloudWatchWAFClient(
            log_group=cloudwatch_log_group,
            region=aws_region,
        )

        self.results: list[TestResult] = []
        self.configs: dict[str, WAFTestConfig] = {}

    def discover_configs(self) -> dict[str, WAFTestConfig]:
        """Discover waf_requirements.yaml files from modules directory."""
        configs = {}

        if not self.modules_root.exists():
            print(f"Warning: Modules root not found: {self.modules_root}")
            return configs

        for yaml_file in self.modules_root.rglob("waf_requirements.yaml"):
            policy_name = yaml_file.parent.name

            try:
                with open(yaml_file) as f:
                    raw = yaml.safe_load(f)

                raw = self._interpolate_config(raw)
                config = WAFTestConfig(**raw)

                for req in config.requirements:
                    req.policy_name = policy_name
                    req.source_file = str(yaml_file)

                configs[policy_name] = config
                print(f"  Loaded: {policy_name} ({len(config.requirements)} requirements)")

            except Exception as e:
                print(f"  Warning: Failed to load {yaml_file}: {e}")

        self.configs = configs
        return configs

    def _interpolate_config(self, data: dict) -> dict:
        """Replace ${VAR} placeholders."""
        def replace_vars(obj):
            if isinstance(obj, str):
                result = obj
                result = result.replace("${WAF_ENDPOINT}", self.waf_endpoint)
                result = result.replace("${AWS_ACCOUNT_ID}", self.account_id)
                result = result.replace("${OWASP_NAMESPACE}", self.owasp_namespace)
                return result
            elif isinstance(obj, dict):
                return {k: replace_vars(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_vars(item) for item in obj]
            return obj
        return replace_vars(data)

    def run_all_tests(self, policy_filter: Optional[str] = None) -> CoverageReport:
        """Run all test cases for specified policy."""
        print("\n" + "=" * 70)
        print("WAF POLICY TEST RUNNER")
        print("=" * 70)
        print(f"Endpoint: {self.waf_endpoint}")
        print(f"Host:     {self.waf_host}")
        print(f"Log Group: {self.cloudwatch_log_group}")
        print("=" * 70)

        if not self.configs:
            self.discover_configs()

        all_results = []
        total_requirements = 0

        for policy_name, config in self.configs.items():
            if policy_filter and policy_name != policy_filter:
                continue

            print(f"\n--- Testing Policy: {policy_name} ---")
            results = self._run_policy_tests(config)
            all_results.extend(results)
            total_requirements += len(config.requirements)

        report = self._generate_coverage_report("all", all_results, total_requirements)
        self._print_coverage_report(report)

        return report

    def _run_policy_tests(self, config: WAFTestConfig) -> list[TestResult]:
        """Run TEST 1 (positive) for each requirement."""
        results = []

        for idx, req in enumerate(config.requirements):
            tuning_type = req.tuning_type or "size_body"  # Default to size_body
            print(f"\n  Requirement: {req.id} [{tuning_type}] ({req.uri})")

            # =================================================================
            # TEST 1: POSITIVE - Fire payload, expect BLOCK (403)
            # =================================================================
            result = self._test_positive(config, req)
            results.append(result)
            self._print_result("TEST 1 [POSITIVE]", result)

        return results

    # =========================================================================
    # TEST 1: POSITIVE - Fire payload and check expected_action
    # =========================================================================
    def _test_positive(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Fire the test payload and verify the result matches expected_action.

        If expected_action is BLOCK: 403 = PASS, anything else = FAIL
        If expected_action is ALLOW: non-403 = PASS, 403 = FAIL
        """
        test_id = f"{req.id}:positive"
        tuning_type = req.tuning_type or "size_body"
        expected_action = req.test_config.expected_action or "ALLOW"

        # Build base request
        uri = req.uri
        body = None

        # Helper: Load body from file if specified
        def load_data_file(file_path: str) -> str:
            """Load content from file, return None if not found."""
            from pathlib import Path
            path = Path(file_path).expanduser()
            if path.exists():
                content = path.read_text()
                print(f"    Loaded {len(content)} bytes from {path}")
                return content
            else:
                print(f"    File not found: {path}, using generated payload")
                return None

        # Customize request based on tuning_type
        if tuning_type == "size_body":
            # Priority 1: Load from data_file if specified
            if req.test_config.data_file:
                print(f"    DEBUG: Loading from data_file: {req.test_config.data_file}")
                body = load_data_file(req.test_config.data_file)
            # Add large body if configured
            if body is None and req.test_config.test_large_body:
                print(f"    DEBUG: Using generated payload of {req.test_config.large_body_size_bytes} bytes")
                body = "X" * req.test_config.large_body_size_bytes

        elif tuning_type == "size_querystring":
            # Add query string for query string size testing
            if req.test_config.test_querystring:
                uri = f"{req.uri}?{req.test_config.test_querystring}"
            elif req.test_config.test_querystring_size > 0:
                # Generate query string of specified size
                qs = "q=" + ("X" * (req.test_config.test_querystring_size - 2))
                uri = f"{req.uri}?{qs}"

        elif tuning_type == "xss":
            # Send XSS payload as raw body for WAF inspection
            if req.test_config.test_payload:
                body = req.test_config.test_payload
            else:
                body = '<div class="user-content">Test</div>'

        elif tuning_type == "sqli":
            # Send SQLi payload in query string AND body for WAF inspection
            if req.test_config.test_query:
                uri = f"{req.uri}?{req.test_config.test_query}"
            elif req.test_config.test_payload:
                # Query string — triggers SQLi_QUERYSTRING detection
                uri = f"{req.uri}?q={req.test_config.test_payload}"
                # Body — triggers SQLi_Body detection
                body = json.dumps({"search": req.test_config.test_payload})

        elif tuning_type == "cmdi":
            # Command injection — send in query string and body
            if req.test_config.test_payload:
                uri = f"{req.uri}?cmd={req.test_config.test_payload}"
                body = req.test_config.test_payload

        elif tuning_type == "lfi":
            # Local file inclusion — send as path in query string
            if req.test_config.test_payload:
                uri = f"{req.uri}?file={req.test_config.test_payload}"
                body = req.test_config.test_payload

        elif tuning_type == "rfi":
            # Remote file inclusion — send as URL in query string
            if req.test_config.test_payload:
                uri = f"{req.uri}?url={req.test_config.test_payload}"
                body = req.test_config.test_payload

        elif tuning_type == "ssti":
            # Template injection — send in body and query string
            if req.test_config.test_payload:
                uri = f"{req.uri}?template={req.test_config.test_payload}"
                body = req.test_config.test_payload

        elif tuning_type == "base64":
            # Base64-encoded payloads — send as-is, WAF should still block
            if req.test_config.test_payload:
                uri = f"{req.uri}?data={req.test_config.test_payload}"
                body = req.test_config.test_payload

        # winshell and default: standard request with no special payload

        request = WAFRequest(
            uri=uri,
            method=req.method,
            host=self.waf_host,  # Use WAF_ENDPOINT host
            headers=dict(req.headers),
            body=body,
        )

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="positive",
                expected_action=expected_action,
                message=f"HTTP error: {response.error}",
            )

        # 502 after all retries = WAF gap (payload bypassed WAF and crashed backend)
        if response.status_code == 502:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="positive",
                expected_action=expected_action,
                actual_action="BACKEND_CRASH",
                http_status=502,
                request_id=request.request_id,
                message="WAF GAP: Payload reached backend and caused 502 (not blocked by WAF)",
                duration_ms=response.duration_ms,
            )

        # If expected_action is BLOCK, a 403 is a PASS
        if expected_action == "BLOCK":
            if response.status_code == 403:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.PASS,
                    test_type="positive",
                    expected_action="BLOCK",
                    actual_action="BLOCK",
                    http_status=response.status_code,
                    request_id=request.request_id,
                    message="Correctly blocked (403)",
                    duration_ms=response.duration_ms,
                )
            else:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.FAIL,
                    test_type="positive",
                    expected_action="BLOCK",
                    actual_action="ALLOW",
                    http_status=response.status_code,
                    request_id=request.request_id,
                    message=f"Expected BLOCK but got {response.status_code}",
                )

        # Query CloudWatch for label verification (ALLOW path)
        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)

        # Select appropriate FP label based on tuning_type
        if tuning_type in ("size_body", "size_querystring"):
            fp_label = req.fp_labels.size
        elif tuning_type == "xss":
            fp_label = req.fp_labels.xss
        elif tuning_type == "sqli":
            fp_label = req.fp_labels.sqli
        else:
            fp_label = req.fp_labels.size  # Default

        if log_entry:
            fp_present = any(fp_label in lbl for lbl in log_entry.labels) if fp_label else False

            if log_entry.action == "ALLOW" and response.status_code != 403:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.PASS,
                    test_type="positive",
                    expected_action="ALLOW",
                    actual_action=log_entry.action,
                    http_status=response.status_code,
                    request_id=request.request_id,
                    expected_labels=[fp_label] if fp_label else [],
                    actual_labels=log_entry.labels,
                    message=f"Allowed with FP label: {fp_label}" if fp_present else "Allowed (no FP label needed)",
                    duration_ms=response.duration_ms,
                )
            else:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.FAIL,
                    test_type="positive",
                    expected_action="ALLOW",
                    actual_action=log_entry.action,
                    http_status=response.status_code,
                    request_id=request.request_id,
                    actual_labels=log_entry.labels,
                    message=f"BLOCKED! Expected ALLOW. FP label present: {fp_present}",
                )

        # No log - check HTTP status
        if response.status_code != 403:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="positive",
                expected_action="ALLOW",
                http_status=response.status_code,
                request_id=request.request_id,
                message="Allowed (no WAF log found)",
            )

        return TestResult(
            test_id=test_id,
            requirement_id=req.id,
            policy_name=config.policy.name,
            status=TestStatus.FAIL,
            test_type="positive",
            expected_action="ALLOW",
            http_status=response.status_code,
            request_id=request.request_id,
            message="Got 403 - request was blocked",
        )

    # =========================================================================
    # TEST 2-6: Commented out - only running TEST 1 (positive) for now
    # =========================================================================
    # def _test_oversized_user_agent(self, config, req): ...    # TEST 2
    # def _test_gamification_sqli(self, config, req): ...       # TEST 3
    # def _test_negative_uri(self, config, req): ...            # TEST 4
    # def _test_oversized_cookie(self, config, req): ...        # TEST 5
    # def _test_large_body_with_injection(self, config, req):...# TEST 6

    # =========================================================================
    # Reporting
    # =========================================================================
    def _print_result(self, label: str, result: TestResult):
        """Print single test result."""
        icons = {TestStatus.PASS: "PASS", TestStatus.FAIL: "FAIL", TestStatus.ERROR: "ERROR", TestStatus.SKIP: "SKIP"}
        icon = icons.get(result.status, "?")
        print(f"    {icon} {label}: {result.message}")

        # Show label comparison
        if result.expected_labels:
            print(f"         Expected labels:    {result.expected_labels}")
        if result.actual_labels:
            print(f"         Actual labels:    {result.actual_labels}")
        if result.actual_action:
            print(f"         WAF Action:    {result.actual_action}")

    def _generate_coverage_report(self, name: str, results: list[TestResult], total_reqs: int) -> CoverageReport:
        """Generate coverage report with breakdown by test type."""
        report = CoverageReport(policy_name=name, total_requirements=total_reqs, results=results)

        tested_reqs = set()

        # Track counts by test type
        test_counts = {
            "positive": {"total": 0, "passed": 0},
            "size_block": {"total": 0, "passed": 0},
            "gamification": {"total": 0, "passed": 0},
            "negative_uri": {"total": 0, "passed": 0},
        }

        for r in results:
            tested_reqs.add(r.requirement_id)

            if r.test_type == "positive":
                test_counts["positive"]["total"] += 1
                if r.status == TestStatus.PASS:
                    test_counts["positive"]["passed"] += 1
            elif r.test_type == "size_block":
                test_counts["size_block"]["total"] += 1
                if r.status == TestStatus.PASS:
                    test_counts["size_block"]["passed"] += 1
            elif r.test_type == "negative_uri":
                test_counts["negative_uri"]["total"] += 1
                if r.status == TestStatus.PASS:
                    test_counts["negative_uri"]["passed"] += 1
            elif r.test_type in ("gamification", "injection"):
                test_counts["gamification"]["total"] += 1
                if r.status == TestStatus.PASS:
                    test_counts["gamification"]["passed"] += 1

        report.tested_requirements = len(tested_reqs)
        report.passed_requirements = len([r for r in results if r.status == TestStatus.PASS])
        report.failed_requirements = len([r for r in results if r.status == TestStatus.FAIL])

        # Update legacy fields for backwards compatibility
        report.positive_tests = test_counts["positive"]["total"]
        report.positive_passed = test_counts["positive"]["passed"]
        report.negative_tests = test_counts["negative_uri"]["total"]
        report.negative_passed = test_counts["negative_uri"]["passed"]
        report.injection_tests = test_counts["gamification"]["total"]
        report.injection_passed = test_counts["gamification"]["passed"]

        # Store size_block counts in report
        report._size_block_counts = test_counts["size_block"]

        return report

    def _print_coverage_report(self, report: CoverageReport):
        """Print coverage summary."""
        total_tests = len(report.results)
        passed = len([r for r in report.results if r.status == TestStatus.PASS])
        failed = len([r for r in report.results if r.status == TestStatus.FAIL])

        # Get size_block counts (TEST 2 + TEST 5)
        size_counts = getattr(report, '_size_block_counts', {"total": 0, "passed": 0})

        print("\n" + "=" * 70)
        print(f"COVERAGE REPORT: {report.policy_name}")
        print("=" * 70)
        print(f"Total Tests:      {total_tests}")
        print(f"  Passed:         {passed}")
        print(f"  Failed:         {failed}")
        print(f"Pass Rate:        {(passed / total_tests * 100) if total_tests else 0:.1f}%")
        print("-" * 70)
        print(f"TEST 1 (Positive):       {report.positive_passed}/{report.positive_tests}")
        print("=" * 70)

        failures = [r for r in report.results if r.status == TestStatus.FAIL]
        if failures:
            print(f"\nFAILED TESTS ({len(failures)}):")
            for f in failures:
                print(f"  FAIL {f.test_id}")
                print(f"    {f.message}")

    def export_json_report(self, report: CoverageReport, output_path: str):
        """Export test results as JSON for ML training pipeline."""
        from datetime import datetime as dt

        results_data = []
        for r in report.results:
            results_data.append({
                "test_id": r.test_id,
                "requirement_id": r.requirement_id,
                "policy_name": r.policy_name,
                "status": r.status.value,
                "test_type": r.test_type,
                "expected_action": r.expected_action,
                "actual_action": r.actual_action,
                "http_status": r.http_status,
                "request_id": r.request_id,
                "expected_labels": r.expected_labels,
                "actual_labels": r.actual_labels,
                "message": r.message,
                "duration_ms": r.duration_ms,
            })

        # Build requirement metadata from configs
        requirements_meta = []
        for policy_name, config in self.configs.items():
            for req in config.requirements:
                requirements_meta.append({
                    "requirement_id": req.id,
                    "policy_name": policy_name,
                    "tuning_type": req.tuning_type,
                    "uri": req.uri,
                    "method": req.method,
                    "host": req.host,
                    "has_xss_fp_label": req.fp_labels.xss is not None,
                    "has_sqli_fp_label": req.fp_labels.sqli is not None,
                    "has_size_fp_label": req.fp_labels.size is not None,
                    "has_test_payload": req.test_config.test_payload is not None,
                    "expected_action": req.test_config.expected_action,
                })

        json_report = {
            "timestamp": dt.utcnow().isoformat() + "Z",
            "waf_endpoint": self.waf_endpoint,
            "summary": {
                "policy": report.policy_name,
                "total_requirements": report.total_requirements,
                "tested": report.tested_requirements,
                "passed": report.passed_requirements,
                "failed": report.failed_requirements,
                "pass_rate": round(report.pass_rate, 2),
                "coverage_percent": round(report.coverage_percent, 2),
            },
            "results": results_data,
            "requirements_metadata": requirements_meta,
        }

        with open(output_path, "w") as f:
            json.dump(json_report, f, indent=2)

        print(f"\nJSON report exported to: {output_path}")

    def close(self):
        """Clean up."""
        self.http.close()
