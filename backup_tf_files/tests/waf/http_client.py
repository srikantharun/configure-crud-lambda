"""HTTP client for sending test requests to WAF-protected endpoints."""
from __future__ import annotations

import uuid
import time
import requests
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class WAFRequest:
    """Structured WAF test request."""
    uri: str
    method: str
    host: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    query_params: Optional[dict] = None
    request_id: Optional[str] = None

    def __post_init__(self):
        if not self.request_id:
            self.request_id = f"waf-test-{uuid.uuid4()}"
        # Always inject request ID for CloudWatch tracing
        self.headers["X-Request-Id"] = self.request_id


@dataclass
class WAFResponse:
    """Response from WAF test request."""
    status_code: int
    request_id: str
    headers: dict
    body: str
    duration_ms: float = 0
    error: Optional[str] = None


class WAFHttpClient:
    """HTTP client for WAF testing with retry and timeout handling."""

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
        max_retries: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def send(self, request: WAFRequest) -> WAFResponse:
        """Send request through WAF and return response."""
        url = f"{self.base_url}{request.uri}"

        headers = dict(request.headers)
        headers["Host"] = request.host

        start_time = time.time()

        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    data=request.body,
                    params=request.query_params,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                duration_ms = (time.time() - start_time) * 1000

                return WAFResponse(
                    status_code=response.status_code,
                    request_id=request.request_id,
                    headers=dict(response.headers),
                    body=response.text[:2000],  # Truncate large bodies
                    duration_ms=duration_ms,
                )

            except requests.Timeout:
                if attempt == self.max_retries - 1:
                    return WAFResponse(
                        status_code=0,
                        request_id=request.request_id,
                        headers={},
                        body="",
                        error=f"Request timed out after {self.timeout}s",
                    )
                time.sleep(1)  # Brief pause before retry

            except requests.ConnectionError as e:
                if attempt == self.max_retries - 1:
                    return WAFResponse(
                        status_code=0,
                        request_id=request.request_id,
                        headers={},
                        body="",
                        error=f"Connection error: {e}",
                    )
                time.sleep(1)

            except requests.RequestException as e:
                return WAFResponse(
                    status_code=0,
                    request_id=request.request_id,
                    headers={},
                    body="",
                    error=str(e),
                )

        # Should not reach here
        return WAFResponse(
            status_code=0,
            request_id=request.request_id,
            headers={},
            body="",
            error="Max retries exceeded",
        )

    def send_with_large_body(
        self,
        request: WAFRequest,
        body_size_bytes: int,
        body_pattern: str = "X",
    ) -> WAFResponse:
        """Send request with generated large body."""
        request.body = body_pattern * body_size_bytes
        return self.send(request)

    def send_with_oversized_header(
        self,
        request: WAFRequest,
        header_name: str,
        size_bytes: int,
    ) -> WAFResponse:
        """Send request with oversized header."""
        request.headers[header_name] = "X" * size_bytes
        return self.send(request)

    def close(self):
        """Close the session."""
        self.session.close()
