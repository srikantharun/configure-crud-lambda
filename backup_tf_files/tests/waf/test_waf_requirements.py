"""
WAF Requirements Test Suite

Pytest-based tests that:
1. Discover waf_requirements.yaml from each custom module
2. Run positive/negative/injection tests for each requirement
3. Verify via CloudWatch logs
4. Generate coverage reports
"""
from __future__ import annotations

import pytest
from .models import WAFTestConfig, WAFRequirement
from .test_runner import WAFTestRunner


class TestWAFRequirements:
    """Test WAF requirements using the test runner."""

    def _print_result(self, test_name, result):
          """Print label comparison details."""
          print(f"\n  ─── {test_name} ───")
          print(f"  Request ID:      {result.request_id}")
          print(f"  HTTP Status:     {result.http_status}")
          print(f"  Expected Action: {result.expected_action}")
          print(f"  Actual Action:   {result.actual_action}")
          print(f"  Expected Labels: {result.expected_labels}")
          print(f"  Actual Labels:   {result.actual_labels}")
          print(f"  Result:          {result.status.value.upper()}")
          print(f"  Message:         {result.message}")

    def test_valid_request_allowed(self, test_runner, config, requirement):
          """TEST 1: Valid request should be allowed with FP label."""
          result = test_runner._test_positive(config, requirement)
          self._print_result("TEST 1 POSITIVE", result)
          assert result.status.value == "pass", f"Failed: {result.message}"

#     def test_oversized_user_agent_blocked(self, test_runner, config, requirement):
#           """TEST 2: Oversized User-Agent should be blocked."""
#           result = test_runner._test_oversized_user_agent(config, requirement)
#           self._print_result("TEST 2 UA SIZE", result)
#           assert result.status.value == "pass", f"Failed: {result.message}"

#     def test_oversized_cookie_blocked(self, test_runner, config, requirement):
#           """TEST 5: Oversized Cookie should be blocked."""
#           result = test_runner._test_oversized_cookie(config, requirement)
#           self._print_result("TEST 5 COOKIE SIZE", result)
#           assert result.status.value == "pass", f"Failed: {result.message}"

#     def test_negative_uri_blocked(self, test_runner, config, requirement):
#           """TEST 4: Tampered URI should be blocked."""
#           result = test_runner._test_negative_uri(config, requirement)
#           self._print_result("TEST 4 NEGATIVE URI", result)
#           assert result.status.value == "pass", f"Failed: {result.message}"

#     def test_gamification_sqli_blocked(self, test_runner, config, requirement):
#           """TEST 3: SQLi should be blocked even with FP conditions."""
#           if "sqli" not in config.labels.supported_checks:
#               pytest.skip("SQLi not in supported_checks")
#           result = test_runner._test_gamification_sqli(config, requirement)
#           self._print_result("TEST 3 GAMIFICATION", result)
#           assert result.status.value == "pass", f"Failed: {result.message}"

    @pytest.mark.padded_injection
    @pytest.mark.size_limit
    def test_padded_injection_blocked(
        self,
        test_runner: WAFTestRunner,
        config: WAFTestConfig,
        requirement: WAFRequirement,
    ):
          """
          Test 6: Large padded body (1MB) with Log4j injection should be BLOCKED.

          Verifies that attackers cannot bypass injection detection by padding
          requests with large bodies (within tuned size limits up to 10MB).
          """
          # Only run for size_body tuning type
          if requirement.tuning_type != "size_body":
             pytest.skip(f"Padded injection test only runs for size_body tuning type")

          result = test_runner._test_large_body_with_injection(config, requirement)
          self._print_result("TEST 6 Large padded body testing", result)
          assert result.status.value == "pass", f"Failed: {result.message}"
