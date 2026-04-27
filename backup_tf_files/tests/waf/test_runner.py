"""
WAF Test Runner (GET variant) - Executes GET-method test cases and generates coverage reports.

Differences vs test_runner.py:
- Discovers `waf_requirements_get.yaml` (not `waf_requirements.yaml`)
- Payload placement is method-aware:
    * xss/cmdi/lfi/rfi/ssti/base64 + GET -> payload URL-encoded into ?q=
    * sqli + GET                         -> payload URL-encoded into ?q=, no body
    * non-GET methods                    -> payload in JSON body (legacy POST behaviour preserved)
- Body is force-cleared on GET requests so the WAF inspects QUERY_STRING only.
"""
from __future__ import annotations

import json
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


DEFAULT_REQUIREMENTS_FILENAME = "waf_requirements.yaml"


class WAFTestRunner:
    """
    Method-aware WAF test runner.

    POST requirements (legacy): payload placed in JSON body of `/rest/user/login`.
    GET  requirements        : payload URL-encoded into a query parameter; no body.

    The YAML filename to discover is configurable via `requirements_filename`,
    so a single runner can drive either a POST suite (`waf_requirements.yaml`)
    or a GET suite (`waf_requirements_get.yaml`).
    """

    MAX_HEADER_SIZE_BYTES = 8 * 1024  # 8KB
    NEGATIVE_URI_BODY_SIZE = 68000
    NEGATIVE_URI_PREFIX = "/mytest"

    def __init__(
        self,
        waf_endpoint: str,
        cloudwatch_log_group: str,
        aws_region: str = "eu-west-1",
        account_id: str = "",
        owasp_namespace: str = "owasp",
        modules_root: Optional[Path] = None,
        negative_uri_prefix: str = "/mytest",
        requirements_filename: str = DEFAULT_REQUIREMENTS_FILENAME,
    ):
        self.waf_endpoint = waf_endpoint
        self.cloudwatch_log_group = cloudwatch_log_group
        self.account_id = account_id
        self.owasp_namespace = owasp_namespace
        self.negative_uri_prefix = negative_uri_prefix
        self.requirements_filename = requirements_filename

        parsed = urlparse(waf_endpoint)
        self.waf_host = parsed.netloc or parsed.path.split('/')[0]

        self.modules_root = modules_root or Path(__file__).parent.parent.parent / "modules" / "custom"

        self.http = WAFHttpClient(base_url=waf_endpoint)
        self.cw = CloudWatchWAFClient(
            log_group=cloudwatch_log_group,
            region=aws_region,
        )

        self.results: list[TestResult] = []
        self.configs: dict[str, WAFTestConfig] = {}

    def discover_configs(self) -> dict[str, WAFTestConfig]:
        """Discover requirements YAML files from modules directory."""
        configs = {}

        if not self.modules_root.exists():
            print(f"Warning: Modules root not found: {self.modules_root}")
            return configs

        for yaml_file in self.modules_root.rglob(self.requirements_filename):
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
                print(f"  Loaded: {policy_name} ({len(config.requirements)} requirements) [{self.requirements_filename}]")

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
        """Run all GET test cases for specified policy."""
        print("\n" + "=" * 70)
        print("WAF POLICY TEST RUNNER (GET)")
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
        per_request_delay = 2

        for idx, req in enumerate(config.requirements):
            if idx > 0:
                time.sleep(per_request_delay)

            tuning_type = req.tuning_type or "size_querystring"
            print(f"\n  Requirement: {req.id} [{tuning_type}] ({req.method} {req.uri})")

            result = self._test_positive(config, req)
            results.append(result)
            self._print_result("TEST 1 [POSITIVE]", result)

        return results

    # =========================================================================
    # TEST 1: POSITIVE - Fire payload and check expected_action
    # =========================================================================
    def _test_positive(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        test_id = f"{req.id}:positive"
        tuning_type = req.tuning_type or "size_querystring"
        expected_action = req.test_config.expected_action or "ALLOW"
        is_get = (req.method or "").upper() == "GET"

        uri = req.uri
        body = None

        def load_data_file(file_path: str) -> Optional[str]:
            path = Path(file_path).expanduser()
            if path.exists():
                content = path.read_text()
                print(f"    Loaded {len(content)} bytes from {path}")
                return content
            print(f"    File not found: {path}, using generated payload")
            return None

        # ------------------------------------------------------------------
        # Build payload placement, method-aware
        # ------------------------------------------------------------------
        if tuning_type == "size_body":
            # size_body is a POST-only test — keep legacy behaviour
            if req.test_config.data_file:
                body = load_data_file(req.test_config.data_file)
            if body is None and req.test_config.test_large_body:
                body = "X" * req.test_config.large_body_size_bytes

        elif tuning_type == "size_querystring":
            if req.test_config.test_querystring:
                uri = f"{req.uri}?{req.test_config.test_querystring}"
            elif req.test_config.test_querystring_size > 0:
                qs = "q=" + ("X" * (req.test_config.test_querystring_size - 2))
                uri = f"{req.uri}?{qs}"

        elif tuning_type in ("xss", "cmdi", "lfi", "rfi", "ssti", "base64"):
            payload = req.test_config.test_payload
            if payload is not None:
                if is_get:
                    uri = f"{req.uri}?q={quote(str(payload), safe='')}"
                else:
                    body = json.dumps({"email": str(payload), "password": "test"})

        elif tuning_type == "sqli":
            payload = req.test_config.test_payload
            if req.test_config.test_query:
                uri = f"{req.uri}?{req.test_config.test_query}"
            elif payload is not None:
                if is_get:
                    uri = f"{req.uri}?q={quote(str(payload), safe='')}"
                else:
                    uri = f"{req.uri}?q={payload}"  # raw, matches legacy POST behaviour
            if not is_get and payload is not None:
                body = json.dumps({"email": str(payload), "password": "test"})

        # ------------------------------------------------------------------
        # Final safety guard: GET must never carry a body
        # ------------------------------------------------------------------
        if is_get and body is not None:
            body = None

        headers = dict(req.headers)
        headers["X-Test-Id"] = req.id
        headers["X-Test-Category"] = tuning_type
        payload_summary = str(req.test_config.test_payload or "")[:50].replace("\n", " ")
        headers["X-Test-Payload"] = payload_summary
        # Strip body-related headers on GET so origin/CDN don't reject the request
        if is_get:
            headers.pop("Content-Type", None)
            headers.pop("Content-Length", None)

        request = WAFRequest(
            uri=uri,
            method=req.method,
            host=self.waf_host,
            headers=headers,
            body=body,
        )

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

        # 500/502 = WAF gap (payload bypassed WAF, backend error)
        if response.status_code in (500, 502):
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="positive",
                expected_action=expected_action,
                actual_action="BACKEND_ERROR",
                http_status=response.status_code,
                request_id=request.request_id,
                message=f"WAF GAP: Payload reached backend and caused {response.status_code} (not blocked by WAF)",
                duration_ms=response.duration_ms,
            )

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

        # ALLOW path — no FP label verification
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
    # Reporting
    # =========================================================================
    def _print_result(self, label: str, result: TestResult):
        icons = {TestStatus.PASS: "PASS", TestStatus.FAIL: "FAIL", TestStatus.ERROR: "ERROR", TestStatus.SKIP: "SKIP"}
        icon = icons.get(result.status, "?")
        print(f"    {icon} {label}: {result.message}")

        if result.expected_labels:
            print(f"         Expected labels: {result.expected_labels}")
        if result.actual_labels:
            print(f"         Actual labels:   {result.actual_labels}")
        if result.actual_action:
            print(f"         WAF Action:      {result.actual_action}")

    def _generate_coverage_report(self, name: str, results: list[TestResult], total_reqs: int) -> CoverageReport:
        report = CoverageReport(policy_name=name, total_requirements=total_reqs, results=results)

        tested_reqs = set()
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

        report.positive_tests = test_counts["positive"]["total"]
        report.positive_passed = test_counts["positive"]["passed"]
        report.negative_tests = test_counts["negative_uri"]["total"]
        report.negative_passed = test_counts["negative_uri"]["passed"]
        report.injection_tests = test_counts["gamification"]["total"]
        report.injection_passed = test_counts["gamification"]["passed"]

        report._size_block_counts = test_counts["size_block"]
        return report

    def _print_coverage_report(self, report: CoverageReport):
        total_tests = len(report.results)
        passed = len([r for r in report.results if r.status == TestStatus.PASS])
        failed = len([r for r in report.results if r.status == TestStatus.FAIL])

        print("\n" + "=" * 70)
        print(f"COVERAGE REPORT (GET): {report.policy_name}")
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
                    "has_test_payload": req.test_config.test_payload is not None,
                    "expected_action": req.test_config.expected_action,
                })

        json_report = {
            "timestamp": dt.utcnow().isoformat() + "Z",
            "waf_endpoint": self.waf_endpoint,
            "method_profile": "GET",
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
        self.http.close()
