"""
Cryptographic utility for signing and verifying egress envelopes.
Provides tamper detection, non-repudiation, and tenant authentication.
"""

import hmac
import hashlib
import json
from typing import Dict, Any


def compute_signature(secret_key: str, payload_dict: Dict[str, Any]) -> str:
    """Compute HMAC-SHA256 signature over canonical JSON representation."""
    # Ensure signature field is excluded when calculating signature
    clean_dict = {k: v for k, v in payload_dict.items() if k != "signature"}
    canonical_json = json.dumps(clean_dict, sort_keys=True, separators=(',', ':'))
    return hmac.new(
        secret_key.encode('utf-8'),
        canonical_json.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_signature(secret_key: str, payload_dict: Dict[str, Any], expected_signature: str) -> bool:
    """Safely verify HMAC signature with constant-time comparison."""
    if not expected_signature:
        return False
    computed = compute_signature(secret_key, payload_dict)
    return hmac.compare_digest(computed, expected_signature)


def hash_identifier(identifier: str, salt: str = "salt_v1") -> str:
    """One-way irreversible pseudonymous hash for correlating entities without leaking identities."""
    return hashlib.sha256(f"{salt}:{identifier}".encode('utf-8')).hexdigest()[:16]
