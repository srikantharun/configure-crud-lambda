"""Pytest configuration and fixtures for WAF testing."""
from __future__ import annotations

import os
import pytest
import yaml
from pathlib import Path
from typing import Iterator, Optional

from .waf.models import WAFTestConfig, WAFRequirement
from .waf.http_client import WAFHttpClient
from .waf.cloudwatch_client import CloudWatchWAFClient
from .waf.test_runner import WAFTestRunner


# Path to modules directory (relative to repo root)
MODULES_ROOT = Path(__file__).parent.parent / "modules"


def pytest_addoption(parser):
    """Add custom CLI options for WAF testing."""
    parser.addoption(
        "--waf-module",
        action="store",
        default=None,
        help="Filter tests to specific module (e.g., payme_global_v8, ease_global_v7)",
    )
    parser.addoption(
        "--waf-endpoint",
        action="store",
        default=os.getenv("WAF_ENDPOINT", "https://waf-test.example.com"),
        help="WAF endpoint URL",
    )
    parser.addoption(
        "--waf-log-group",
        action="store",
        default=os.getenv("WAF_LOG_GROUP", "aws-waf-logs-test"),
        help="CloudWatch log group",
    )
    parser.addoption(
        "--aws-region",
        action="store",
        default=os.getenv("AWS_REGION", "eu-west-1"),
        help="AWS region for CloudWatch",
    )
    parser.addoption(
        "--account-id",
        action="store",
        default=os.getenv("AWS_ACCOUNT_ID", ""),
        help="AWS account ID for label interpolation",
    )
    parser.addoption(
        "--owasp-namespace",
        action="store",
        default=os.getenv("OWASP_NAMESPACE", "owasp"),
        help="OWASP rule label namespace",
    )
    parser.addoption(
        "--coverage-threshold",
        action="store",
        type=float,
        default=80.0,
        help="Minimum coverage percentage required to pass",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "positive: valid request should be allowed")
    config.addinivalue_line("markers", "negative: invalid request should be blocked")
    config.addinivalue_line("markers", "injection: XSS/SQLi attack tests")
    config.addinivalue_line("markers", "xss: XSS injection tests")
    config.addinivalue_line("markers", "sqli: SQL injection tests")
    config.addinivalue_line("markers", "size_limit: header/body size limit tests")
    config.addinivalue_line("markers", "padded_injection: padded body injection tests")


@pytest.fixture(scope="session")
def session_config(request) -> dict:
    """Gather all CLI options into a config dict."""
    return {
        "waf_endpoint": request.config.getoption("--waf-endpoint"),
        "waf_log_group": request.config.getoption("--waf-log-group"),
        "aws_region": request.config.getoption("--aws-region"),
        "account_id": request.config.getoption("--account-id"),
        "owasp_namespace": request.config.getoption("--owasp-namespace"),
        "module_filter": request.config.getoption("--waf-module"),
        "coverage_threshold": request.config.getoption("--coverage-threshold"),
    }


@pytest.fixture(scope="session")
def http_client(session_config) -> Iterator[WAFHttpClient]:
    """Create HTTP client for WAF requests."""
    client = WAFHttpClient(base_url=session_config["waf_endpoint"])
    yield client
    client.close()


@pytest.fixture(scope="session")
def cw_client(session_config) -> CloudWatchWAFClient:
    """Create CloudWatch client for log verification."""
    return CloudWatchWAFClient(
        log_group=session_config["waf_log_group"],
        region=session_config["aws_region"],
    )


@pytest.fixture(scope="session")
def test_runner(session_config) -> Iterator[WAFTestRunner]:
    """Create test runner instance."""
    runner = WAFTestRunner(
        waf_endpoint=session_config["waf_endpoint"],
        cloudwatch_log_group=session_config["waf_log_group"],
        aws_region=session_config["aws_region"],
        account_id=session_config["account_id"],
        owasp_namespace=session_config["owasp_namespace"],
        modules_root=MODULES_ROOT,
    )
    runner.discover_configs()
    yield runner
    runner.close()


def discover_configs(module_filter: str=None) -> list[tuple[WAFTestConfig, str]]:
    """Discover all waf_requirements.yaml files from modules directory."""
    configs = []

    if not MODULES_ROOT.exists():
        print(f"Warning: Modules root not found: {MODULES_ROOT}")
        return configs

    for yaml_file in MODULES_ROOT.rglob("waf_requirements.yaml"):
        policy_name = yaml_file.parent.name

        if module_filter and policy_name != module_filter:
           continue

        try:
            with open(yaml_file) as f:
                raw = yaml.safe_load(f)

            config = WAFTestConfig(**raw)

            for req in config.requirements:
                req.policy_name = policy_name
                req.source_file = str(yaml_file)

            configs.append((config, policy_name))
        except Exception as e:
            print(f"Warning: Failed to load {yaml_file}: {e}")

    return configs


def pytest_generate_tests(metafunc):
    """Dynamically parametrize tests based on discovered configs."""
    if "config" in metafunc.fixturenames and "requirement" in metafunc.fixturenames:
        module_filter = metafunc.config.getoption("--waf-module")

        params = []
        for config, policy_name in discover_configs(module_filter):
            for req in config.requirements:
                params.append(pytest.param(
                    config,
                    req,
                    id=f"{policy_name}:{req.id}",
                ))

        if params:
            metafunc.parametrize("config,requirement", params)
