# Secure AIOps Observability Platform (Two-Tier Architecture)

A production-ready reference implementation and architecture for privacy-first, secure enterprise observability.

This platform solves the critical data sovereignty challenge: **monitoring distributed infrastructure, applications, and security events without exposing sensitive raw operational data, PII, credentials, or proprietary payloads outside the customer's environment.**

---

## Key Features

1. **Two-Tier Architecture**:
   - **Local Collector (Tier 1)**: Deployed inside customer VPC/on-premises environment. Collects telemetry, scrubs PII/credentials, stores raw data in local encrypted storage, and executes real-time streaming **Edge AIOps** (EWMA latency anomaly detection, error budget burn rates, log template fingerprinting).
   - **Centralized SaaS Platform (Tier 2)**: Receives strictly validated, cryptographically signed metadata envelopes (SLI/SLO health metrics, quantiles, and alerts). Runs **Global AIOps** for cross-service causal inference, root-cause analysis (RCA), and incident triaging—with **zero raw data exposure**.
2. **Guaranteed Zero-Data Egress**:
   - Outbound Egress Gateway validates that no prohibited raw keys (`raw_log`, `password`, `query`, `body`, `payload`) ever leave the perimeter.
   - HMAC-SHA256 signature guarantees tamper resistance and non-repudiation.
   - Outbound-only TLS connections: zero inbound ports opened into customer networks.
3. **Federated Forensics**:
   - Full raw logs are retained locally with short configurable TTL (e.g., 24-72h) for internal SRE debugging via local CLI.

---

## Directory Structure

```
secure-aiops-platform/
├── ARCHITECTURE.md             # In-depth architectural blueprint and threat model
├── README.md                   # Quickstart guide and overview
├── demo.py                     # Interactive end-to-end simulation runner
├── common/
│   ├── __init__.py
│   ├── models.py               # Strictly typed data schemas for the two-tier contract
│   └── crypto_utils.py         # HMAC-SHA256 signing and verification
├── local_collector/
│   ├── __init__.py
│   ├── sanitizer.py            # High-performance PII, token, & credential redactor
│   ├── local_storage.py        # Local encrypted SQLite buffer for raw data retention
│   ├── edge_aiops.py           # Real-time streaming EWMA & statistical anomaly detector
│   └── egress_gateway.py       # Egress firewall & outbound transmitter
├── saas_platform/
│   ├── __init__.py
│   ├── global_aiops.py         # Multi-service causal correlator & RCA engine
│   └── saas_server.py          # Centralized Ingestion API & live Web Dashboard
└── tests/
    ├── __init__.py
    └── test_platform.py        # Automated test suite verifying all security invariants
```

---

## Quickstart

### 1. Run Automated Unit Tests
Verify all security invariants, PII redactor, edge EWMA detector, and HMAC signatures:
```bash
python3 tests/test_platform.py
```

### 2. Run the Interactive End-to-End Simulation
Run the complete lifecycle simulation:
```bash
python3 demo.py
```

The script will:
1. Initialize the Central SaaS Control Plane and local customer collector.
2. Ingest realistic customer transactions containing credit cards, SSNs, JWTs, and database query strings.
3. Retain 100% of raw data locally and prove zero customer secrets leave the perimeter.
4. Inject a database connection pool exhaustion failure.
5. Trigger local Edge AIOps streaming detection (EWMA latency anomaly + error rate spike).
6. Seal and transmit the egress envelope to the central SaaS platform.
7. Run SaaS Global AIOps to correlate signals into an actionable incident with Root Cause Analysis (`postgres-db connection pool exhaustion -> checkout-api cascading failure`).
8. Perform a mathematical zero-leakage audit.

### 3. Open the Central SaaS Dashboard in Browser
When the SaaS server is running, navigate to:
```
http://127.0.0.1:8088/?tenant_id=tenant-fintech-corp
```
This presents a live, dark-mode dashboard displaying:
- **Tenant Health Index** (calculated from edge indicators)
- **Sensitive Data Prevented from Egress** counter
- **AIOps Correlated Root Cause Incidents** with recommended runbooks
- **Statistical Service Health Metrics** (p50, p95, p99, error rates)
- **Live Egress Wire Payload** demonstrating 0% raw data transfer

---

### 4. Standalone Local Collector CLI (`local_collector.cli`)

Run the standalone on-premises agent directly from the project root:

```bash
# Normal continuous streaming (default interval: 5s)
python3 -m local_collector.cli

# Run once and exit
python3 -m local_collector.cli --once

# Live hackathon demo: inject cascading failure & outage
python3 -m local_collector.cli --simulate-outage --interval 3

# View local storage and offline buffer status
python3 -m local_collector.cli --status

# SRE Forensics drilldown into unredacted local records
python3 -m local_collector.cli --query-local postgres-db
python3 -m local_collector.cli --query-local --filter password
```

*(Note: `python3 -m local_collector.clip` is also supported as an alias)*
