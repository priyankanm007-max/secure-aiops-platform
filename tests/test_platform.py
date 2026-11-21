"""
Automated unit & integration test suite for the Secure Two-Tier AIOps Platform.
Verifies security invariants, zero-data leakage, edge anomaly detection, and SaaS correlation.
"""

import unittest
import time
import uuid
import json
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.models import RawTelemetryEvent, EgressEnvelope, HealthMetric, TelemetrySummary, EdgeAlert
from common.crypto_utils import compute_signature, verify_signature
from local_collector.sanitizer import TelemetrySanitizer
from local_collector.local_storage import LocalTelemetryStore
from local_collector.edge_aiops import EdgeAIOpsEngine
from local_collector.egress_gateway import OutboundEgressGateway, EgressPolicyViolationError
from saas_platform.global_aiops import GlobalAIOpsEngine
from saas_platform.saas_server import run_saas_server


class TestSecureAIOpsPlatform(unittest.TestCase):

    def setUp(self):
        self.sanitizer = TelemetrySanitizer()
        self.store = LocalTelemetryStore(":memory:")
        self.edge_aiops = EdgeAIOpsEngine()
        self.tenant_id = "tenant-fintech-corp"
        self.secret_key = "fintech-super-secret-hmac-key-2026"

    def test_pii_sanitization(self):
        """Test that sensitive credentials and customer PII are redacted."""
        raw_log = (
            "POST /api/checkout User john.doe@example.com purchased with card 4532-1234-5678-9012. "
            "SSN: 987-65-4321, Authorization: Bearer secret-auth-token-1234567890, "
            "DB URI: postgres://dbuser:supersecretpass@db.internal:5432/finances"
        )
        sanitized, redaction_count = self.sanitizer.sanitize_text(raw_log)

        self.assertGreaterEqual(redaction_count, 5)
        self.assertNotIn("4532-1234-5678-9012", sanitized)
        self.assertNotIn("987-65-4321", sanitized)
        self.assertNotIn("john.doe@example.com", sanitized)
        self.assertNotIn("secret-auth-token-1234567890", sanitized)
        self.assertNotIn("supersecretpass", sanitized)

        self.assertIn("[REDACTED_CREDIT_CARD]", sanitized)
        self.assertIn("[REDACTED_SSN]", sanitized)
        self.assertIn("[REDACTED_EMAIL]", sanitized)
        self.assertIn("[REDACTED_TOKEN]", sanitized)
        self.assertIn("[REDACTED_PWD]", sanitized)

    def test_local_storage_raw_persistence(self):
        """Test that raw payloads are retained locally in customer SQLite database."""
        event = RawTelemetryEvent(
            event_id="evt-100",
            timestamp=time.time(),
            service="auth-service",
            environment="production-onprem",
            event_type="security",
            raw_payload="User admin login failed with bad password 'pass1234' from IP 192.168.1.50"
        )
        self.store.store_event(event)
        self.assertEqual(self.store.get_event_count(), 1)
        self.assertGreater(self.store.get_total_raw_bytes(), 0)

        # Internal operator can query locally
        records = self.store.query_local_raw_by_service("auth-service")
        self.assertEqual(len(records), 1)
        self.assertIn("pass1234", records[0]["raw_payload"])

    def test_edge_aiops_anomaly_detection(self):
        """Test streaming EWMA anomaly detection on p99 latency spikes and error rate."""
        service = "payment-service"

        # Baseline: 50 requests with low normal latency (15 - 25 ms)
        for _ in range(50):
            self.edge_aiops.record_metric(service, latency_ms=20.0, status_code=200)

        metric, alerts = self.edge_aiops.evaluate_service_health(service)
        self.assertEqual(metric.status, "HEALTHY")
        self.assertEqual(len(alerts), 0)

        # Sudden anomaly: inject high latency spike (900 ms) and 500 errors
        for _ in range(30):
            self.edge_aiops.record_metric(service, latency_ms=950.0, status_code=500)

        metric, alerts = self.edge_aiops.evaluate_service_health(service)
        self.assertIn(metric.status, ["DEGRADED", "CRITICAL"])
        self.assertGreaterEqual(len(alerts), 1)
        alert_titles = [a.title for a in alerts]
        self.assertTrue(any("Latency Anomaly" in t or "Error Rate" in t for t in alert_titles))

    def test_egress_firewall_blocks_prohibited_keys(self):
        """Test that the outbound egress gateway strictly blocks any attempt to send raw data."""
        gateway = OutboundEgressGateway(
            tenant_id=self.tenant_id,
            collector_id="collector-node-01",
            secret_key=self.secret_key,
            saas_endpoint="http://127.0.0.1:8088/api/v1/telemetry/egress"
        )

        # Legitimate envelope
        valid_envelope = EgressEnvelope(
            tenant_id=self.tenant_id,
            collector_id="collector-node-01",
            timestamp=time.time(),
            health_indicators=[
                HealthMetric(
                    service="checkout",
                    status="HEALTHY",
                    cpu_percent=15.0,
                    memory_percent=30.0,
                    p50_latency_ms=12.0,
                    p95_latency_ms=25.0,
                    p99_latency_ms=35.0,
                    requests_per_sec=100.0,
                    error_rate_percent=0.1,
                    active_connections=10
                )
            ]
        )
        # Should succeed inspection and seal with signature
        payload_dict = gateway.prepare_envelope(valid_envelope)
        self.assertIn("signature", payload_dict)

        # Attempt to leak raw payload into metadata -> MUST BE REJECTED
        violating_envelope = EgressEnvelope(
            tenant_id=self.tenant_id,
            collector_id="collector-node-01",
            timestamp=time.time(),
            alerts=[
                EdgeAlert(
                    alert_id="a1",
                    timestamp=time.time(),
                    service="auth",
                    severity="CRITICAL",
                    rule_or_model="test",
                    title="test",
                    description="test",
                    confidence=0.9,
                    suggested_runbook="runbook",
                    context_indicators={"raw_log": "SELECT * FROM users WHERE pass='123'"}
                )
            ]
        )
        with self.assertRaises(EgressPolicyViolationError):
            gateway.prepare_envelope(violating_envelope)

    def test_saas_hmac_verification_and_correlation(self):
        """Test SaaS reception, cryptographic signature verification, and multi-service correlation."""
        saas_engine = GlobalAIOpsEngine()

        # Build an envelope reporting alerts on both database and upstream checkout API
        envelope_dict = {
            "tenant_id": self.tenant_id,
            "collector_id": "collector-node-01",
            "timestamp": time.time(),
            "schema_version": "2.0-strict",
            "health_indicators": [
                {
                    "service": "postgres-db",
                    "status": "CRITICAL",
                    "cpu_percent": 95.0,
                    "memory_percent": 88.0,
                    "p50_latency_ms": 250.0,
                    "p95_latency_ms": 1100.0,
                    "p99_latency_ms": 2500.0,
                    "requests_per_sec": 450.0,
                    "error_rate_percent": 12.0,
                    "active_connections": 100
                },
                {
                    "service": "checkout-api",
                    "status": "DEGRADED",
                    "cpu_percent": 45.0,
                    "memory_percent": 50.0,
                    "p50_latency_ms": 180.0,
                    "p95_latency_ms": 950.0,
                    "p99_latency_ms": 2100.0,
                    "requests_per_sec": 120.0,
                    "error_rate_percent": 24.0,
                    "active_connections": 50
                }
            ],
            "summaries": {
                "window_start": time.time() - 60,
                "window_end": time.time(),
                "total_events_processed": 1500,
                "raw_bytes_retained_locally": 450000,
                "log_level_distribution": {"INFO": 1400, "ERROR": 100},
                "error_fingerprints": {"a1b2c3d4e5f6": 100},
                "status_codes": {"200": 1350, "500": 150}
            },
            "alerts": [
                {
                    "alert_id": "alt-db-01",
                    "timestamp": time.time(),
                    "service": "postgres-db",
                    "severity": "CRITICAL",
                    "rule_or_model": "Edge-EWMA-Latency-Spike",
                    "title": "Database Query Bottleneck",
                    "description": "p99 latency 2500ms exceeded normal baseline",
                    "confidence": 0.96,
                    "suggested_runbook": "scale-db-connections",
                    "context_indicators": {"p99_ms": 2500.0}
                },
                {
                    "alert_id": "alt-api-01",
                    "timestamp": time.time(),
                    "service": "checkout-api",
                    "severity": "CRITICAL",
                    "rule_or_model": "Edge-SLO-Error-Budget-Exhaustion",
                    "title": "Elevated 5xx Error Rate",
                    "description": "5xx errors reached 24.0%",
                    "confidence": 0.98,
                    "suggested_runbook": "inspect-upstream-dependencies",
                    "context_indicators": {"error_rate_pct": 24.0}
                }
            ]
        }

        # Compute valid signature
        signature = compute_signature(self.secret_key, envelope_dict)
        self.assertTrue(verify_signature(self.secret_key, envelope_dict, signature))

        # Ingest into SaaS
        incidents = saas_engine.ingest_envelope(envelope_dict)
        self.assertGreaterEqual(len(incidents), 1)

        # Causal inference should detect cascading failure
        cascade = incidents[0]
        self.assertEqual(cascade.severity, "CRITICAL")
        self.assertIn("postgres-db", cascade.probable_root_cause)
        self.assertIn("checkout-api", cascade.affected_services)

        # Check tenant health index
        health_index = saas_engine.compute_tenant_health_index(self.tenant_id)
        self.assertLess(health_index, 60.0)  # Degraded health score

    def test_cli_field_allowlisting(self):
        """Test strict field allowlisting drops unknown fields."""
        from local_collector.cli import apply_field_allowlist

        dirty_envelope = {
            "tenant_id": self.tenant_id,
            "collector_id": "us-east-onprem-collector-01",
            "timestamp": time.time(),
            "schema_version": "2.0-strict",
            "unauthorized_root_field": "secret_debug_dump",
            "health_indicators": [
                {
                    "service": "checkout-api",
                    "status": "HEALTHY",
                    "cpu_percent": 25.0,
                    "memory_percent": 35.0,
                    "p50_latency_ms": 10.0,
                    "p95_latency_ms": 20.0,
                    "p99_latency_ms": 30.0,
                    "requests_per_sec": 50.0,
                    "error_rate_percent": 0.0,
                    "active_connections": 10,
                    "internal_debug_token": "leak_attempt"
                }
            ],
            "summaries": {
                "window_start": 100.0,
                "window_end": 110.0,
                "total_events_processed": 50,
                "raw_bytes_retained_locally": 12000,
                "log_level_distribution": {"INFO": 50},
                "error_fingerprints": {},
                "status_codes": {"200": 50},
                "raw_queries_dump": "SELECT * FROM secrets"
            }
        }

        clean = apply_field_allowlist(dirty_envelope)
        self.assertNotIn("unauthorized_root_field", clean)
        self.assertNotIn("internal_debug_token", clean["health_indicators"][0])
        self.assertNotIn("raw_queries_dump", clean["summaries"])
        self.assertIn("tenant_id", clean)
        self.assertIn("service", clean["health_indicators"][0])

    def test_local_disk_buffering_and_deduplication(self):
        """Test local offline buffering and deduplication when SaaS is unreachable."""
        store = LocalTelemetryStore(":memory:")
        env_id = "env-test-01"
        env_hash = "hash-test-01"
        payload = {"tenant_id": "test", "metrics": []}

        # 1. Buffer first time -> Should succeed
        is_new = store.buffer_envelope(env_id, env_hash, time.time(), payload)
        self.assertTrue(is_new)
        self.assertEqual(store.get_buffered_count(), 1)

        # 2. Buffer same hash again -> Deduplication should ignore
        is_dup = store.buffer_envelope("env-test-02", env_hash, time.time(), payload)
        self.assertFalse(is_dup)
        self.assertEqual(store.get_buffered_count(), 1)

        # 3. Retrieve and delete after transmission
        buffered = store.get_buffered_envelopes()
        self.assertEqual(len(buffered), 1)
        self.assertEqual(buffered[0]["envelope_id"], env_id)

        store.delete_buffered_envelope(env_id)
        self.assertEqual(store.get_buffered_count(), 0)

    def test_cli_agent_cycle_and_zero_leakage_proof(self):
        """Test full LocalCollectorAgent cycle in both normal and simulated outage modes."""
        from local_collector.cli import LocalCollectorAgent
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db") as db_file, tempfile.NamedTemporaryFile(suffix=".log") as log_file:
            agent = LocalCollectorAgent(
                tenant_id=self.tenant_id,
                collector_id="test-collector",
                secret_key=self.secret_key,
                db_path=db_file.name,
                egress_proof_log=log_file.name
            )

            # Normal Cycle
            res_normal = agent.process_cycle(simulate_outage=False)
            self.assertGreater(res_normal["events_ingested"], 0)
            self.assertGreater(res_normal["raw_bytes_retained_locally"], 0)
            self.assertIn(res_normal["delivery_status"], ["DELIVERED_DIRECT", "BUFFERED_OFFLINE"])

            # Verify local raw events contain secrets but egress proof confirms 0 leaks
            raw_records = agent.store.query_local_raw()
            self.assertGreater(len(raw_records), 0)

            # Outage Cycle
            res_outage = agent.process_cycle(simulate_outage=True)
            self.assertGreater(len(res_outage["alerts"]), 0)
            alert_titles = [a.title for a in res_outage["alerts"]]
            self.assertTrue(any("Error Rate" in t or "Latency" in t for t in alert_titles))

            # Verify egress proof log was written
            with open(log_file.name, "r") as f:
                lines = f.readlines()
                self.assertGreaterEqual(len(lines), 2)
                proof = json.loads(lines[0])
                self.assertTrue(proof["security_invariants"]["zero_egress_guaranteed"])
                self.assertEqual(proof["security_invariants"]["customer_secrets_leaked"], 0)


if __name__ == "__main__":
    unittest.main()
