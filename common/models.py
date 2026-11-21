"""
Data models and schemas defining the strict two-tier contract.
Zero raw data leaves the customer boundary.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import json
import time


@dataclass
class RawTelemetryEvent:
    """Raw telemetry collected strictly INSIDE customer environment."""
    event_id: str
    timestamp: float
    service: str
    environment: str
    event_type: str  # 'log', 'metric', 'trace', 'security'
    raw_payload: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthMetric:
    """Approved health indicators - aggregated statistical indicators only."""
    service: str
    status: str  # 'HEALTHY', 'DEGRADED', 'CRITICAL'
    cpu_percent: float
    memory_percent: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    requests_per_sec: float
    error_rate_percent: float
    active_connections: int


@dataclass
class TelemetrySummary:
    """Sanitized aggregate metrics over a time window."""
    window_start: float
    window_end: float
    total_events_processed: int
    raw_bytes_retained_locally: int
    log_level_distribution: Dict[str, int]
    error_fingerprints: Dict[str, int]  # Hash of error template -> count (no raw params)
    status_codes: Dict[str, int]


@dataclass
class EdgeAlert:
    """High-fidelity alert generated locally at the edge without raw payloads."""
    alert_id: str
    timestamp: float
    service: str
    severity: str  # 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    rule_or_model: str
    title: str
    description: str  # Abstracted, sanitized summary
    confidence: float
    suggested_runbook: str
    context_indicators: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EgressEnvelope:
    """The strictly bounded outbound contract sent to SaaS platform.
    
    GUARANTEE: No raw logs, no payload bodies, no unhashed credentials, no PII.
    """
    tenant_id: str
    collector_id: str
    timestamp: float
    schema_version: str = "2.0-strict"
    health_indicators: List[HealthMetric] = field(default_factory=list)
    summaries: Optional[TelemetrySummary] = None
    alerts: List[EdgeAlert] = field(default_factory=list)
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
