"""Pydantic models for WAF test configuration and results."""
from __future__ import annotations

from enum import Enum
from typing import Optional, Any
from dataclasses import dataclass, field
from pydantic import BaseModel, Field


class CheckType(str, Enum):
    """Types of WAF checks."""
    SIZE = "size"
    XSS = "xss"
    SQLI = "sqli"


class TestStatus(str, Enum):
    """Test execution status."""
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


# =============================================================================
# Configuration Models (from waf_requirements.yaml)
# =============================================================================

class DetectionLabels(BaseModel):
    """Labels added by detection rules."""
    size: Optional[str] = None
    size_cookie: Optional[str] = None
    size_querystring: Optional[str] = None
    xss: Optional[str] = None
    sqli: Optional[str] = None
    sqli_querystring: Optional[str] = None
    custom_size: Optional[str] = None


class FalsePositiveNamespaces(BaseModel):
    """Namespace prefixes for false positive labels."""
    size: Optional[str] = None
    xss: Optional[str] = None
    sqli: Optional[str] = None


class PolicyLabels(BaseModel):
    """Label configuration for a WAF policy."""
    detection: DetectionLabels
    false_positive_namespace: FalsePositiveNamespaces = Field(default_factory=FalsePositiveNamespaces)
    supported_checks: list[str] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    """Top-level policy metadata."""
    name: str
    description: str
    waf_endpoint: str = "${WAF_ENDPOINT}"
    cloudwatch_log_group: str
    account_id: str = "${AWS_ACCOUNT_ID}"


class RequirementFPLabels(BaseModel):
    """False positive labels for a requirement."""
    size: Optional[str] = None
    xss: Optional[str] = None
    sqli: Optional[str] = None


class TestConfigMetadata(BaseModel):
    """Test-specific configuration for a requirement."""
    # Body size testing
    # Data file (takes priority over generated payload)
    data_file: Optional[str] = None 

    # Fallback if data_file is not specified
    test_large_body: bool = False
    large_body_size_bytes: int = 0

    # Query string testing (for size_querystring tuning)
    test_querystring: Optional[str] = None
    test_querystring_size: int = 0

    # XSS/SQLi testing
    test_payload: Optional[str] = None  # For XSS/SQLi false positive testing
    test_query: Optional[str] = None    # For query parameter testing

    # SQLi gamification
    test_sqli_with_fp_conditions: bool = False
    sqli_payload: Optional[str] = None

    # Expected outcomes
    expected_action: Optional[str] = None
    expected_labels: list[str] = Field(default_factory=list)
    expected_detection_label: Optional[str] = None


class TuningType(str, Enum):
    """Types of WAF rule tuning."""
    SIZE_BODY = "size_body"
    SIZE_QUERYSTRING = "size_querystring"
    XSS = "xss"
    SQLI = "sqli"
    WINSHELL = "winshell"
    CMDI = "cmdi"
    LFI = "lfi"
    RFI = "rfi"
    SSTI = "ssti"
    BASE64 = "base64"


class WAFRequirement(BaseModel):
    """A single allowlist requirement from waf_requirements.yaml."""
    id: str
    description: str
    uri: str
    method: str
    host: str
    tuning_type: Optional[str] = None  # size_body, size_querystring, xss, sqli, winshell
    headers: dict[str, str] = Field(default_factory=dict)
    fp_labels: RequirementFPLabels = Field(default_factory=RequirementFPLabels)
    test_config: TestConfigMetadata = Field(default_factory=TestConfigMetadata)

    # Populated at load time
    policy_name: Optional[str] = None
    source_file: Optional[str] = None


class SizeBlockingTest(BaseModel):
    """Size restriction blocking test scenario."""
    name: str
    description: Optional[str] = None
    uri: Optional[str] = None
    header: Optional[str] = None
    size_bytes: int = 0
    body_size_bytes: int = 0
    expected_action: str
    expected_label: Optional[str] = None


class InjectionPayload(BaseModel):
    """Injection payload for testing."""
    payload: str
    description: str


class TestScenarios(BaseModel):
    """Additional test scenarios."""
    size_blocking: list[SizeBlockingTest] = Field(default_factory=list)
    injection_always_blocked: list[dict] = Field(default_factory=list)


class InjectionTests(BaseModel):
    """Injection test configuration."""
    verify_no_bypass: bool = True
    sqli: list[InjectionPayload] = Field(default_factory=list)
    xss: list[InjectionPayload] = Field(default_factory=list)


class WAFTestConfig(BaseModel):
    """Complete test configuration from waf_requirements.yaml."""
    policy: PolicyConfig
    labels: PolicyLabels
    requirements: list[WAFRequirement]
    test_scenarios: Optional[TestScenarios] = None
    injection_tests: Optional[InjectionTests] = None


# =============================================================================
# Result Models
# =============================================================================

class WAFLogEntry(BaseModel):
    """Parsed CloudWatch WAF log entry."""
    timestamp: int = 0
    request_id: str
    action: str  # ALLOW, BLOCK, COUNT
    terminating_rule_id: Optional[str] = None
    terminating_rule_type: Optional[str] = None
    labels: list[str] = Field(default_factory=list)
    http_status: Optional[int] = None
    raw: dict = Field(default_factory=dict)


@dataclass
class TestResult:
    """Result of a single test case."""
    test_id: str
    requirement_id: str
    policy_name: str
    status: TestStatus
    test_type: str  # positive, negative, injection, size_blocking
    expected_action: str
    actual_action: Optional[str] = None
    http_status: int = 0
    request_id: str = ""
    expected_labels: list[str] = field(default_factory=list)
    actual_labels: list[str] = field(default_factory=list)
    message: str = ""
    duration_ms: float = 0


@dataclass
class CoverageReport:
    """Test coverage report for a policy."""
    policy_name: str
    total_requirements: int = 0
    tested_requirements: int = 0
    passed_requirements: int = 0
    failed_requirements: int = 0
    skipped_requirements: int = 0

    # Detailed breakdown
    positive_tests: int = 0
    positive_passed: int = 0
    negative_tests: int = 0
    negative_passed: int = 0
    injection_tests: int = 0
    injection_passed: int = 0

    results: list[TestResult] = field(default_factory=list)

    @property
    def coverage_percent(self) -> float:
        if self.total_requirements == 0:
            return 0.0
        return (self.tested_requirements / self.total_requirements) * 100

    @property
    def pass_rate(self) -> float:
        if self.tested_requirements == 0:
            return 0.0
        return (self.passed_requirements / self.tested_requirements) * 100

    @property
    def uncovered_requirements(self) -> list[str]:
        tested = {r.requirement_id for r in self.results}
        # This would need to be populated from config
        return []
