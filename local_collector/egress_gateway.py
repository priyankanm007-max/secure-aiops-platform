"""
Outbound Egress Gateway.
The security checkpoint and air-gap enforcement layer.
Inspects every outbound packet, verifies compliance with the Zero-Raw-Data contract,
signs with tenant HMAC, and delivers to the SaaS endpoint.
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple
from common.models import EgressEnvelope
from common.crypto_utils import compute_signature


class EgressPolicyViolationError(Exception):
    """Raised when an outbound payload attempts to leak raw or prohibited data."""
    pass


class OutboundEgressGateway:
    """Enforces zero-data-leakage outbound firewall."""

    # Explicitly forbidden keys that must never appear anywhere in the egress payload
    FORBIDDEN_KEYS = {
        "raw_log", "log_message", "message", "query", "sql", "payload",
        "body", "stack_trace", "raw_payload", "headers", "password", "secret",
        "ssn", "credit_card", "email", "authorization"
    }

    def __init__(self, tenant_id: str, collector_id: str, secret_key: str, saas_endpoint: str, in_process_sink=None):
        self.tenant_id = tenant_id
        self.collector_id = collector_id
        self.secret_key = secret_key
        self.saas_endpoint = saas_endpoint
        self.in_process_sink = in_process_sink

    def audit_for_forbidden_data(self, obj: Any, path: str = "$") -> None:
        """Recursively scan data structure to guarantee no raw or sensitive fields exist."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                lower_k = str(k).lower()
                if lower_k in self.FORBIDDEN_KEYS:
                    raise EgressPolicyViolationError(
                        f"Security Egress Violation! Forbidden raw telemetry key '{k}' found at path '{path}.{k}'"
                    )
                self.audit_for_forbidden_data(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self.audit_for_forbidden_data(item, f"{path}[{idx}]")

    def prepare_envelope(self, envelope: EgressEnvelope) -> Dict[str, Any]:
        """Verify, sign, and seal outbound envelope."""
        payload_dict = envelope.to_dict()

        # Step 1: Deep inspection for forbidden keys or payload leaks
        self.audit_for_forbidden_data(payload_dict)

        # Step 2: Sign envelope cryptographically with tenant secret
        signature = compute_signature(self.secret_key, payload_dict)
        payload_dict["signature"] = signature

        return payload_dict

    def transmit(self, envelope: EgressEnvelope) -> Tuple[bool, str]:
        """Transmit verified envelope to central SaaS platform."""
        try:
            payload_dict = self.prepare_envelope(envelope)

            if self.in_process_sink:
                res = self.in_process_sink(payload_dict)
                return True, f"Success (In-Process Egress): {res}"

            json_bytes = json.dumps(payload_dict).encode('utf-8')

            req = urllib.request.Request(
                self.saas_endpoint,
                data=json_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Tenant-ID": self.tenant_id,
                    "X-Collector-ID": self.collector_id
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp_body = resp.read().decode('utf-8')
                return True, f"Success ({resp.status}): {resp_body}"

        except EgressPolicyViolationError as e:
            return False, f"BLOCKED BY EGRESS FIREWALL: {str(e)}"
        except Exception as e:
            if self.in_process_sink:
                res = self.in_process_sink(payload_dict)
                return True, f"Success (Sandbox In-Process Fallback): {res}"
            return False, f"Network Transmission Error: {str(e)}"
