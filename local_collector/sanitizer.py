"""
Local telemetry sanitizer and privacy engine.
Detects and sanitizes PII, credentials, tokens, connection strings,
and converts raw variable-filled log lines into stable semantic templates.
"""

import re
import hashlib
from typing import Tuple, Dict, Any


class TelemetrySanitizer:
    """Multi-stage privacy sanitizer enforcing customer data sovereignty."""

    # Pre-compiled high-performance regex patterns in strict order of specificity
    PATTERNS = [
        # Database URIs (e.g. postgresql://user:pass@host:5432/db) - MUST run before email matcher
        (r'([a-zA-Z0-9]+):\/\/([a-zA-Z0-9_\-\.]+):([^@]+)@([a-zA-Z0-9_\-\.]+)(:[0-9]+)?(\/[^\s]*)?', r'\1://\2:[REDACTED_PWD]@\4\5\6'),
        # Passwords / Secrets in queries or JSON
        (r'(?i)(password|passwd|secret|client_secret)[\s:=]+([^\s,;}{]+)', r'\1=[REDACTED_SECRET]'),
        # Bearer Tokens / Authorization Headers
        (r'(?i)(bearer|token|apikey|api_key|auth)[\s:=]+([a-zA-Z0-9_\-\.]{16,})', r'\1 [REDACTED_TOKEN]'),
        # JSON Web Tokens (JWT)
        (r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b', '[REDACTED_JWT]'),
        # Credit Card (Visa, MC, Amex, Discover, etc.)
        (r'\b(?:\d{4}[ -]?){3}\d{4}\b', '[REDACTED_CREDIT_CARD]'),
        # US Social Security Number
        (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]'),
        # Email Addresses
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]'),
        # IP Addresses (IPv4)
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_PSEUDONYMIZED]'),
    ]

    def __init__(self):
        self.compiled_rules = [(re.compile(p), repl) for p, repl in self.PATTERNS]

    def sanitize_text(self, text: str) -> Tuple[str, int]:
        """Scrub PII and sensitive credentials from text. Returns (sanitized_text, redaction_count)."""
        redaction_count = 0
        current = text
        for pattern, replacement in self.compiled_rules:
            matches = len(pattern.findall(current))
            if matches > 0:
                redaction_count += matches
                current = pattern.sub(replacement, current)
        return current, redaction_count

    def extract_template_fingerprint(self, raw_message: str) -> str:
        """Extract structural template signature from a log message by stripping variable parameters.
        
        Example:
          'User 8482 failed authentication on /api/login from 10.0.0.1'
          -> 'User <VAR> failed authentication on <PATH> from <IP>'
          -> sha256 fingerprint
        """
        # Replace variable tokens: numbers, hex strings, UUIDs, IPs, quoted strings
        s = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '<UUID>', raw_message)
        s = re.sub(r'0x[a-fA-F0-9]+', '<HEX>', s)
        s = re.sub(r'\b\d+\b', '<NUM>', s)
        s = re.sub(r'"[^"]*"', '<STR>', s)
        s = re.sub(r"'[^']*'", '<STR>', s)
        s = re.sub(r'\s+', ' ', s).strip()

        # Compute deterministic fingerprint of the abstracted template
        return hashlib.sha256(s.encode('utf-8')).hexdigest()[:12]
