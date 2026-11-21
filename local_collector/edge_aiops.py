"""
Edge AIOps Intelligence Engine.
Performs streaming online anomaly detection, statistical profiling,
and health state evaluation right where data is produced.
"""

import math
import time
import uuid
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, deque
from common.models import HealthMetric, EdgeAlert, TelemetrySummary


class EWMAAnomalyDetector:
    """Exponentially Weighted Moving Average with dynamic variance bounds.
    Detects sudden latency or error rate anomalies in real-time streaming data.
    """

    def __init__(self, alpha: float = 0.2, z_threshold: float = 3.0):
        self.alpha = alpha
        self.z_threshold = z_threshold
        self.mean: Optional[float] = None
        self.variance: float = 0.0

    def update(self, value: float) -> Tuple[bool, float, float]:
        """Update tracker with new observation.
        Returns (is_anomaly, current_mean, z_score).
        """
        if self.mean is None:
            self.mean = value
            self.variance = 1.0  # Initial baseline
            return False, self.mean, 0.0

        diff = value - self.mean
        std_dev = math.sqrt(max(self.variance, 1e-4))
        z_score = diff / std_dev

        # Update running stats
        self.mean = (1 - self.alpha) * self.mean + self.alpha * value
        self.variance = (1 - self.alpha) * self.variance + self.alpha * (diff ** 2)

        is_anomaly = z_score > self.z_threshold
        return is_anomaly, self.mean, z_score


class EdgeAIOpsEngine:
    """Local AIOps processor running inside the customer environment."""

    def __init__(self):
        # Per-service latency detectors
        self.latency_trackers: Dict[str, EWMAAnomalyDetector] = defaultdict(
            lambda: EWMAAnomalyDetector(alpha=0.25, z_threshold=2.8)
        )
        # Recent sliding window of request latencies
        self.latency_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # Status code counters
        self.status_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Log level counts
        self.log_level_counts: Dict[str, int] = defaultdict(int)
        # Template fingerprint counters
        self.fingerprint_counts: Dict[str, int] = defaultdict(int)

    def record_metric(self, service: str, latency_ms: float, status_code: int):
        """Ingest individual transaction telemetry for edge streaming analysis."""
        self.latency_windows[service].append(latency_ms)
        self.status_counters[service][str(status_code)] += 1

    def record_log(self, level: str, fingerprint: str):
        """Ingest log classification event."""
        self.log_level_counts[level] += 1
        self.fingerprint_counts[fingerprint] += 1

    def evaluate_service_health(self, service: str, cpu: float = 25.0, mem: float = 40.0) -> Tuple[HealthMetric, List[EdgeAlert]]:
        """Calculate health indicators and generate alerts based on edge AIOps detection."""
        alerts: List[EdgeAlert] = []
        samples = list(self.latency_windows[service])
        
        if not samples:
            # Default healthy baseline if no traffic
            return HealthMetric(
                service=service,
                status="HEALTHY",
                cpu_percent=cpu,
                memory_percent=mem,
                p50_latency_ms=10.0,
                p95_latency_ms=25.0,
                p99_latency_ms=40.0,
                requests_per_sec=0.0,
                error_rate_percent=0.0,
                active_connections=5
            ), alerts

        samples.sort()
        n = len(samples)
        p50 = samples[int(n * 0.50)]
        p95 = samples[int(n * 0.95)]
        p99 = samples[int(n * 0.99)]

        # Calculate error rate
        status_map = self.status_counters[service]
        total_reqs = sum(status_map.values()) or 1
        error_reqs = sum(count for code, count in status_map.items() if code.startswith('5') or code.startswith('4'))
        error_rate = (error_reqs / total_reqs) * 100.0

        # Run EWMA Anomaly Detection on p99 latency
        is_latency_anomaly, baseline, z_score = self.latency_trackers[service].update(p99)

        # Status determination
        status = "HEALTHY"
        if error_rate > 15.0 or p99 > 800.0 or is_latency_anomaly:
            status = "CRITICAL" if (error_rate > 30.0 or p99 > 1500.0) else "DEGRADED"

        # Generate intelligent Edge Alert if anomaly detected
        if is_latency_anomaly and p99 > 100.0:
            alerts.append(EdgeAlert(
                alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                service=service,
                severity="CRITICAL" if z_score > 4.0 else "WARNING",
                rule_or_model="Edge-EWMA-Latency-Spike",
                title=f"Statistical Latency Anomaly on {service}",
                description=f"p99 latency ({p99:.1f}ms) deviated by {z_score:.2f} sigma from rolling baseline ({baseline:.1f}ms).",
                confidence=min(0.99, 0.70 + (z_score * 0.05)),
                suggested_runbook="inspect-upstream-dependencies-and-db-pool",
                context_indicators={
                    "observed_p99_ms": round(p99, 2),
                    "baseline_ms": round(baseline, 2),
                    "z_score": round(z_score, 2),
                    "error_rate_pct": round(error_rate, 2)
                }
            ))

        if error_rate > 20.0:
            alerts.append(EdgeAlert(
                alert_id=f"alert-{uuid.uuid4().hex[:8]}",
                timestamp=time.time(),
                service=service,
                severity="CRITICAL",
                rule_or_model="Edge-SLO-Error-Budget-Exhaustion",
                title=f"Elevated 5xx Error Rate on {service}",
                description=f"Error rate reached {error_rate:.1f}% exceeding acceptable SLO threshold (5.0%).",
                confidence=0.98,
                suggested_runbook="restart-failing-pods-or-rollback-canary",
                context_indicators={
                    "error_rate_pct": round(error_rate, 2),
                    "total_samples": total_reqs
                }
            ))

        metric = HealthMetric(
            service=service,
            status=status,
            cpu_percent=cpu,
            memory_percent=mem,
            p50_latency_ms=round(p50, 2),
            p95_latency_ms=round(p95, 2),
            p99_latency_ms=round(p99, 2),
            requests_per_sec=round(n / 10.0, 1),
            error_rate_percent=round(error_rate, 2),
            active_connections=12
        )

        return metric, alerts

    def build_summary(self, window_start: float, window_end: float, total_raw_bytes: int) -> TelemetrySummary:
        """Produce an aggregated summary without exposing raw records."""
        # Top error fingerprints (top 5 most frequent error templates)
        top_fingerprints = dict(sorted(self.fingerprint_counts.items(), key=lambda item: item[1], reverse=True)[:5])

        total_status_codes = defaultdict(int)
        for svc_codes in self.status_counters.values():
            for code, cnt in svc_codes.items():
                total_status_codes[code] += cnt

        total_events = sum(self.log_level_counts.values()) + sum(total_status_codes.values())

        return TelemetrySummary(
            window_start=window_start,
            window_end=window_end,
            total_events_processed=total_events,
            raw_bytes_retained_locally=total_raw_bytes,
            log_level_distribution=dict(self.log_level_counts),
            error_fingerprints=top_fingerprints,
            status_codes=dict(total_status_codes)
        )
