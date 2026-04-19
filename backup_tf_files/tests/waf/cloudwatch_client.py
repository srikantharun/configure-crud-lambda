"""CloudWatch Logs client for WAF log verification."""
from __future__ import annotations

import json
import time
import boto3
from datetime import datetime, timedelta
from typing import Optional

from .models import WAFLogEntry


class CloudWatchWAFClient:
    """Client to query WAF logs from CloudWatch for verification."""

    def __init__(
        self,
        log_group: str,
        region: str = "eu-west-1",
        max_wait_seconds: int = 30,
        poll_interval: float = 2.0,
    ):
        self.client = boto3.client("logs", region_name=region)
        self.log_group = log_group
        self.max_wait_seconds = max_wait_seconds
        self.poll_interval = poll_interval

    def find_log_by_request_id(
        self,
        request_id: str,
        start_time: Optional[datetime] = None,
    ) -> Optional[WAFLogEntry]:
        """
        Poll CloudWatch until we find the WAF log for this request ID.
        WAF logs typically appear within 5-10 seconds.
        """
        start_time = start_time or (datetime.utcnow() - timedelta(minutes=2))
        start_ts = int(start_time.timestamp() * 1000)
        deadline = time.time() + self.max_wait_seconds

        while time.time() < deadline:
            try:
                response = self.client.filter_log_events(
                    logGroupName=self.log_group,
                    startTime=start_ts,
                    filterPattern=f'"{request_id}"',
                    limit=10,
                )

                for event in response.get("events") or []:
                    entry = self._parse_log_event(event, request_id)
                    if entry and entry.request_id == request_id:
                        return entry

            except self.client.exceptions.ResourceNotFoundException:
                raise ValueError(f"Log group not found: {self.log_group}")
            except Exception as e:
                print(f"CloudWatch query error (retrying): {e}")

            time.sleep(self.poll_interval)

        return None

    def _parse_log_event(self, event: dict, expected_request_id: str) -> Optional[WAFLogEntry]:
        """Parse a CloudWatch log event into WAFLogEntry."""
        try:
            data = json.loads(event.get("message") or "{}")
        except json.JSONDecodeError:
            return None

        # Extract request ID from headers (handle None values)
        request_id = ""
        http_request = data.get("httpRequest") or {}
        headers = http_request.get("headers") or []
        for header in headers:
            if not header:
                continue
            if (header.get("name") or "").lower() == "x-request-id":
                request_id = header.get("value") or ""
                break

        if request_id != expected_request_id:
            return None

        # Extract ALL labels from various sources
        labels = self._extract_all_labels(data)

        return WAFLogEntry(
            timestamp=data.get("timestamp") or 0,
            request_id=request_id,
            action=data.get("action") or "UNKNOWN",
            terminating_rule_id=data.get("terminatingRuleId"),
            terminating_rule_type=data.get("terminatingRuleType"),
            labels=labels,
            http_status=data.get("responseCodeSent"),
            raw=data,
        )

    def _extract_all_labels(self, log_data: dict) -> list[str]:
        """Extract labels from all sources in WAF log."""
        if not log_data:
            return []

        labels = []

        # 1. Top-level labels array
        for label in log_data.get("labels") or []:
            if label and "name" in label:
                labels.append(label["name"])

        # 2. Labels from rule groups
        for rg in log_data.get("ruleGroupList") or []:
            if not rg:
                continue
            rg_id = rg.get("ruleGroupId") or ""

            # Non-terminating rules (COUNT mode)
            for rule in rg.get("nonTerminatingMatchingRules") or []:
                if not rule:
                    continue
                rule_id = rule.get("ruleId") or ""
                action = rule.get("action") or ""

                for detail in rule.get("ruleMatchDetails") or []:
                    if not detail:
                        continue
                    condition_type = detail.get("conditionType") or ""
                    if condition_type:
                        labels.append(condition_type)

                if action == "COUNT" and rule_id:
                    labels.append(f"count:{rg_id}:{rule_id}")

            # Terminating rules
            terminating_rule = rg.get("terminatingRule")
            if terminating_rule:
                rule_id = terminating_rule.get("ruleId") or ""

                for detail in terminating_rule.get("ruleMatchDetails") or []:
                    if not detail:
                        continue
                    condition_type = detail.get("conditionType") or ""
                    if condition_type:
                        labels.append(condition_type)

                if rule_id:
                    labels.append(f"terminate:{rg_id}:{rule_id}")

            # Excluded rules
            for excluded in rg.get("excludedRules") or []:
                if not excluded:
                    continue
                if "exclusionType" in excluded:
                    labels.append(f"excluded:{excluded['exclusionType']}")

        # 3. Rate-based rule labels
        for rb_rule in log_data.get("rateBasedRuleList") or []:
            if rb_rule:
                labels.append(f"ratebasedRule:{rb_rule.get('rateBasedRuleId') or ''}")

        # Deduplicate and filter empty
        return list(set(lbl for lbl in labels if lbl))

    def get_recent_logs(
        self,
        limit: int = 10,
        start_time: Optional[datetime] = None,
    ) -> list[WAFLogEntry]:
        """Get recent WAF logs for debugging."""
        start_time = start_time or (datetime.utcnow() - timedelta(hours=1))
        start_ts = int(start_time.timestamp() * 1000)

        try:
            response = self.client.filter_log_events(
                logGroupName=self.log_group,
                startTime=start_ts,
                limit=limit,
            )

            entries = []
            for event in response.get("events") or []:
                try:
                    data = json.loads(event.get("message") or "{}")
                    request_id = ""
                    http_request = data.get("httpRequest") or {}
                    headers = http_request.get("headers") or []
                    for header in headers:
                        if not header:
                            continue
                        if (header.get("name") or "").lower() == "x-request-id":
                            request_id = header.get("value") or ""
                            break

                    entries.append(WAFLogEntry(
                        timestamp=data.get("timestamp") or 0,
                        request_id=request_id,
                        action=data.get("action") or "",
                        terminating_rule_id=data.get("terminatingRuleId"),
                        labels=self._extract_all_labels(data),
                        raw=data,
                    ))
                except json.JSONDecodeError:
                    continue

            return entries

        except Exception as e:
            print(f"Error fetching recent logs: {e}")
            return []
