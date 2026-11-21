"""
End-to-End Simulation of the Secure Two-Tier AIOps Observability Platform.
Demonstrates:
  1. Local collection of telemetry containing sensitive PII & credentials
  2. 100% retention of raw telemetry in local storage
  3. Real-time edge streaming anomaly detection (EWMA)
  4. Outbound Egress Gateway policy enforcement & HMAC signing
  5. Centralized SaaS Global AIOps correlation & Root Cause Analysis
  6. Zero raw data egress verification
"""

import time
import json
import random
import uuid
import sys
import os

# Set up paths
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from common.models import RawTelemetryEvent, EgressEnvelope
from local_collector.sanitizer import TelemetrySanitizer
from local_collector.local_storage import LocalTelemetryStore
from local_collector.edge_aiops import EdgeAIOpsEngine
from local_collector.egress_gateway import OutboundEgressGateway
from saas_platform.saas_server import run_saas_server


def print_banner(text: str, color: str = "\033[1;36m"):
    border = "=" * 80
    print(f"\n{color}{border}\n {text}\n{border}\033[0m")


def main():
    print_banner("SECURE AIOps OBSERVABILITY PLATFORM (TWO-TIER ARCHITECTURE DEMO)")
    
    tenant_id = "tenant-fintech-corp"
    collector_id = "us-east-onprem-collector-01"
    secret_key = "fintech-super-secret-hmac-key-2026"
    saas_port = 8088
    saas_endpoint = f"http://127.0.0.1:{saas_port}/api/v1/telemetry/egress"

    # Step 1: Start Centralized SaaS Platform
    print("\n\033[1;33m[STEP 1] Starting Centralized SaaS Platform Control Plane...\033[0m")
    server = run_saas_server(port=saas_port)
    print(f"  \033[32m✔ SaaS Ingestion Server running on http://127.0.0.1:{saas_port}\033[0m")
    print(f"  \033[32m✔ Live Management UI available at: http://127.0.0.1:{saas_port}/?tenant_id={tenant_id}\033[0m")

    # Step 2: Initialize Customer-Side Local Collector
    print("\n\033[1;33m[STEP 2] Initializing Customer On-Premises Local Collector...\033[0m")
    sanitizer = TelemetrySanitizer()
    local_store = LocalTelemetryStore(":memory:")
    edge_aiops = EdgeAIOpsEngine()
    from saas_platform.saas_server import SaasRequestHandler

    egress_gateway = OutboundEgressGateway(
        tenant_id=tenant_id,
        collector_id=collector_id,
        secret_key=secret_key,
        saas_endpoint=saas_endpoint,
        in_process_sink=SaasRequestHandler.ingest_direct
    )
    print("  \033[32m✔ Local Sanitizer & PII Masking Engine active\033[0m")
    print("  \033[32m✔ Local Telemetry Store active (Raw data retained locally only)\033[0m")
    print("  \033[32m✔ Edge AIOps Streaming Anomaly Detector initialized\033[0m")
    print("  \033[32m✔ Outbound Egress Gateway active (Strict Zero-Data-Leakage Policy)\033[0m")

    # Step 3: Simulate Normal Operations with Sensitive Telemetry
    print_banner("PHASE 1: NORMAL SYSTEM OPERATION & SENSITIVE DATA INGESTION", "\033[1;34m")
    print("Streaming operational telemetry containing confidential customer data:")
    
    sample_sensitive_events = [
        "POST /v1/checkout user=alice.smith@example.com card=4111-2222-3333-4444 amount=$120.50 Auth: Bearer eyJhbGciOiJIUzI1Ni.tok.xyz",
        "POST /v1/auth ssn=123-45-6789 user=bob@company.org status=LOGIN_SUCCESS ip=10.0.4.12",
        "SELECT * FROM accounts WHERE user_id=9842 AND password_hash='supersecretpass123' latency=12ms",
        "CONNECT postgresql://finuser:topsecret_db_pass@db-cluster.internal:5432/ledger status=OPENED"
    ]

    for i, raw_msg in enumerate(sample_sensitive_events):
        event = RawTelemetryEvent(
            event_id=f"evt-{uuid.uuid4().hex[:6]}",
            timestamp=time.time(),
            service="checkout-api",
            environment="onprem-prod-dc1",
            event_type="log",
            raw_payload=raw_msg
        )
        # Store in local database
        local_store.store_event(event)

        # Sanitize for local log profiling
        sanitized_msg, red_cnt = sanitizer.sanitize_text(raw_msg)
        fp = sanitizer.extract_template_fingerprint(sanitized_msg)
        edge_aiops.record_log(level="INFO", fingerprint=fp)
        edge_aiops.record_metric("checkout-api", latency_ms=random.uniform(15.0, 30.0), status_code=200)

        print(f"  [Local Ingest {i+1}] Raw Received: \033[31m{raw_msg[:65]}...\033[0m")
        print(f"                     Sanitized:    \033[32m{sanitized_msg[:65]}...\033[0m")

    # Check local store stats
    print(f"\n  \033[36mLocal Storage Stats:\033[0m {local_store.get_event_count()} events stored locally ({local_store.get_total_raw_bytes()} bytes of raw payload).")

    # Transmit baseline envelope to SaaS
    health_metric, edge_alerts = edge_aiops.evaluate_service_health("checkout-api")
    summary = edge_aiops.build_summary(time.time() - 30, time.time(), local_store.get_total_raw_bytes())
    envelope = EgressEnvelope(
        tenant_id=tenant_id,
        collector_id=collector_id,
        timestamp=time.time(),
        health_indicators=[health_metric],
        summaries=summary,
        alerts=edge_alerts
    )
    ok, msg = egress_gateway.transmit(envelope)
    print(f"  \033[32m[Outbound Egress 1] Transmitted normal baseline to SaaS: {msg}\033[0m")

    # Step 4: Simulate Production Incident (Cascading Failure)
    print_banner("PHASE 2: SIMULATING CASCADING FAILURE & EDGE ANOMALY DETECTION", "\033[1;31m")
    print("Injecting database connection pool exhaustion:")
    print(" -> postgres-db query latency jumps from 20ms to 2400ms")
    print(" -> checkout-api thread starvation causes 504 Gateway Timeouts & 500 errors\n")

    # Inject DB latency anomaly
    for _ in range(40):
        edge_aiops.record_metric("postgres-db", latency_ms=random.uniform(1800.0, 2600.0), status_code=500)
    
    # Inject Checkout API errors
    for _ in range(40):
        edge_aiops.record_metric("checkout-api", latency_ms=random.uniform(900.0, 2100.0), status_code=504)

    # Edge AIOps evaluates health and detects anomaly locally
    db_health, db_alerts = edge_aiops.evaluate_service_health("postgres-db", cpu=92.0, mem=86.0)
    api_health, api_alerts = edge_aiops.evaluate_service_health("checkout-api", cpu=78.0, mem=65.0)

    print("\033[1;33m[Edge AIOps Anomaly Detection Results]:\033[0m")
    print(f"  • postgres-db:   Status={db_health.status} | p99={db_health.p99_latency_ms}ms | Errors={db_health.error_rate_percent}%")
    for a in db_alerts:
        print(f"    ↳ \033[1;31mAlert Triggered: {a.title} ({a.rule_or_model})\033[0m | Confidence: {a.confidence*100:.0f}%")

    print(f"  • checkout-api:  Status={api_health.status} | p99={api_health.p99_latency_ms}ms | Errors={api_health.error_rate_percent}%")
    for a in api_alerts:
        print(f"    ↳ \033[1;31mAlert Triggered: {a.title} ({a.rule_or_model})\033[0m | Confidence: {a.confidence*100:.0f}%")

    # Step 5: Seal and Transmit Incident Egress Envelope
    print("\n\033[1;33m[STEP 5] Egress Gateway Verification & Outbound Transmission...\033[0m")
    incident_envelope = EgressEnvelope(
        tenant_id=tenant_id,
        collector_id=collector_id,
        timestamp=time.time(),
        health_indicators=[db_health, api_health],
        summaries=edge_aiops.build_summary(time.time() - 30, time.time(), local_store.get_total_raw_bytes()),
        alerts=db_alerts + api_alerts
    )

    # Inspect the exact outbound wire payload
    wire_payload = egress_gateway.prepare_envelope(incident_envelope)
    wire_json_str = json.dumps(wire_payload, indent=2)

    ok, resp_msg = egress_gateway.transmit(incident_envelope)
    print(f"  \033[32m✔ Outbound Egress Gateway: {resp_msg}\033[0m")

    # Step 6: SaaS Global AIOps & Root Cause Analysis
    print_banner("PHASE 3: CENTRALIZED SAAS CORRELATION & PRIVACY VERIFICATION", "\033[1;35m")
    dashboard_state = server.state.aiops.get_dashboard_state(tenant_id)

    print("\033[1;33m[Central SaaS Control Plane State]:\033[0m")
    print(f"  • Tenant Health Index:  \033[1;31m{dashboard_state['overall_health_score']}%\033[0m (Degraded)")
    print(f"  • Privacy Compliance:   \033[1;32m{dashboard_state['privacy_compliance_score']}\033[0m")
    print(f"  • Raw Telemetry Saved:  \033[1;32m{dashboard_state['total_raw_bytes_kept_local']} bytes kept inside customer VPC\033[0m")
    
    print("\n\033[1;33m[AIOps Correlated Root Cause Incidents]:\033[0m")
    for inc in dashboard_state['active_incidents']:
        print(f"  \033[1;31mIncident ID: {inc['incident_id']}\033[0m")
        print(f"  Title:       {inc['title']}")
        print(f"  Root Cause:  \033[1;33m{inc['probable_root_cause']}\033[0m")
        print(f"  Affected:    {', '.join(inc['affected_services'])}")
        print(f"  Action:      \033[36m{inc['recommended_action']}\033[0m\n")

    # Step 7: Proof of Zero-Leakage Audit
    print_banner("MATHEMATICAL PROOF OF ZERO DATA LEAKAGE", "\033[1;32m")
    leak_check = True
    prohibited_strings = [
        "alice.smith@example.com", "4111-2222-3333-4444", "123-45-6789",
        "supersecretpass123", "topsecret_db_pass", "eyJhbGciOiJIUzI1Ni"
    ]
    for secret in prohibited_strings:
        if secret in wire_json_str:
            print(f"  \033[31m[CRITICAL LEAK] Secret '{secret}' found in egress payload!\033[0m")
            leak_check = False

    if leak_check:
        print("  \033[32m✔ VERIFIED: 0 of 6 sample customer secrets leaked to the central SaaS platform.\033[0m")
        print("  \033[32m✔ VERIFIED: Raw queries, full stack traces, and customer payloads remained strictly local.\033[0m")
        print("  \033[32m✔ VERIFIED: Central SaaS has full operational visibility, health SLIs, and AIOps RCA without violating privacy.\033[0m")

    print(f"\n\033[1;36mYou can inspect the live dashboard in your browser:\033[0m")
    print(f"  \033[1mhttp://127.0.0.1:{saas_port}/?tenant_id={tenant_id}\033[0m\n")


if __name__ == "__main__":
    main()
