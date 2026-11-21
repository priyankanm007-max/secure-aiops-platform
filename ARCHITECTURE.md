# Secure AIOps Observability Platform: Two-Tier Architecture Specification

## 1. Executive Summary & Problem Context

Modern enterprises operating in regulated industries (healthcare, finance, defense, critical infrastructure) face a core paradox:
- **Operational Necessity**: They require predictive AIOps, cross-service incident correlation, and unified fleet observability to maintain 99.99% reliability across distributed multi-cloud and on-premises environments.
- **Security & Regulatory Risk**: Standard APM and monitoring platforms (e.g., Datadog, Dynatrace, New Relic) rely on streaming raw payloads, SQL queries, stack traces, and unredacted logs directly into multi-tenant cloud backends. This exposes:
  - **Confidential Customer Data (PII/PHI)**: SSNs, credit card numbers, medical records.
  - **Security Secrets**: Bearer tokens, API credentials, private certificates, connection strings.
  - **Intellectual Property**: Proprietary payloads, internal hostnames, and database schemas.
  - **Regulatory Non-Compliance**: Violation of GDPR, HIPAA, PCI-DSS, SOC 2 Type II, and data sovereignty laws.

### The Solution: Two-Tier Edge-Preserving AIOps Architecture
This platform decouples **data collection and raw inspection** from **global intelligence and centralized triage**:
1. **Tier 1 (Customer Perimeter - Local Collector)**: Sits behind the customer firewall. Collects full telemetry, stores raw payloads inside an encrypted local buffer, performs real-time sanitization/tokenization, and executes streaming **Edge AIOps** (EWMA anomaly detection, dynamic thresholding, log template clustering).
2. **Tier 2 (Centralized Control Plane - SaaS Platform)**: Receives strictly bounded, schema-validated, cryptographically signed metadata envelopes (SLI/SLO health indicators, statistical quantiles, error template fingerprints, and anomaly alerts). It runs **Global AIOps** for cross-service causal inference, root cause analysis (RCA), and fleet-wide incident management—with **0% raw payload exposure**.

---

## 2. High-Level Architectural Topology

```mermaid
flowchart TB
    subgraph CustomerEnv["Customer Internal Network / VPC (Tier 1: On-Premises or Private Cloud)"]
        direction TB
        AppServices["Distributed Services\n(Apps, DBs, K8s, Network)"]
        
        subgraph LocalCollector["Local Collector Instance (DaemonSet / Sidecar / VM)"]
            IngestQueue["Telemetry Ingestion\n(OTLP, Syslog, eBPF)"]
            
            subgraph SecurityEngine["Privacy & Security Engine"]
                Sanitizer["PII & Credential Scrubbing\n(Regex, NER, Tokenizer)"]
                Fingerprinter["Log Template Fingerprinter\n(Drain3 / Tree Clustering)"]
            end
            
            subgraph EdgeAIOps["Edge AIOps Engine"]
                EWMA["Streaming EWMA & Z-Score\n(Latency & Throughput Tracking)"]
                ErrorBudget["Error Budget & SLO Burn\n(Rate-of-Change Detection)"]
                EdgeAlertGen["Local Alert Generator\n(Confidence Scoring)"]
            end
            
            subgraph LocalDataPlane["Local Data Sovereignty Store"]
                LocalBuffer[("Encrypted Local Circular Store\nSQLite / DuckDB / Local NVMe\n(Short Retention: 24h - 72h)")]
                LocalAudit["Local Operator CLI & Audit API\n(Internal Authorized Access Only)"]
            end
            
            EgressGW["Outbound Egress Gateway\n• Strict Schema Validation\n• Forbidden Key Inspection\n• HMAC-SHA256 Signing"]
        end
        
        AppServices -->|"Raw Logs, Traces, Metrics"| IngestQueue
        IngestQueue --> LocalBuffer
        IngestQueue --> Sanitizer
        Sanitizer --> Fingerprinter
        Fingerprinter --> EdgeAIOps
        EdgeAIOps --> EgressGW
        LocalBuffer -.-> LocalAudit
    end

    subgraph InternetBoundary["Strict Air-Gap / Outbound-Only TLS 1.3 Boundary"]
        EgressGW ==="Outbound HTTPS (mTLS + HMAC-SHA256)\n[Health Metrics, Digests, Alert Descriptors ONLY]\nNO RAW LOGS & NO INBOUND PORTS"===> SaaSGateway
    end

    subgraph SaaSPlatform["Centralized SaaS Platform (Tier 2: Multi-Tenant Cloud Control Plane)"]
        direction TB
        SaaSGateway["Ingestion API Gateway\n• Tenant Authentication\n• HMAC Verification\n• Schema Enforcement"]
        
        subgraph GlobalAIOpsEngine["Global AIOps Engine"]
            TopologyGraph["Service Topology & Dependency DAG"]
            CausalEngine["Cross-Service Causal Correlator\n(Root Cause Analysis)"]
            HealthIndex["Tenant Health Index Evaluator"]
        end
        
        subgraph SaaSStore["Multi-Tenant Control Store"]
            MetadataTSDB[("Aggregated Metrics TSDB\n(p50, p95, p99, Error Rates)")]
            IncidentDB[("Incident & RCA Store")]
            PrivacyAuditDB[("Cryptographic Audit Trail\n(Proof of Zero Egress)")]
        end
        
        subgraph CentralUI["Centralized Observability Portal"]
            Dashboard["Fleet Health & Service Maps"]
            IncidentTriage["Incident Response & Runbooks"]
            ComplianceView["Zero-Knowledge Compliance Audit"]
        end
        
        SaaSGateway --> GlobalAIOpsEngine
        SaaSGateway --> SaaSStore
        GlobalAIOpsEngine --> SaaSStore
        SaaSStore --> CentralUI
    end
```

---

## 3. Tier 1: Local Collector Deep Dive

The Local Collector is deployed as a lightweight Kubernetes DaemonSet, sidecar, or virtual appliance inside each customer VPC or datacenter zone.

### 3.1 Components & Data Flow
1. **Multi-Protocol Ingestion**:
   - Supports OpenTelemetry Protocol (OTLP/gRPC), Syslog (RFC 5424), Prometheus scrape targets, and eBPF network trace probes.
2. **Local Storage (Data Sovereignty Buffer)**:
   - Persists 100% of raw events with full unredacted payload inside a local SQLite or DuckDB instance mounted on an encrypted volume (AES-XTS-256).
   - Configured with an aggressive circular TTL (e.g., 24 to 72 hours).
   - Serves internal site-reliability engineers (SREs) who have direct VPN/bastion access for deep root-cause forensics without ever exporting the data outside the perimeter.
3. **Multi-Stage Privacy Sanitizer**:
   - **Pattern Scrubbing**: Strips SSNs, Credit Cards (Luhn validated), emails, and IPv4/IPv6 addresses.
   - **Credential Blinding**: Identifies Bearer tokens, JWTs, HTTP Authorization headers, and database connection strings (`user:password@host`), replacing them with cryptographic hashes or constant markers (`[REDACTED_SECRET]`).
   - **Template Fingerprinting**: Strips variable numbers, UUIDs, and hex values from log strings to compute semantic template hashes (e.g., converting `"User 984 failed auth from 10.0.1.2"` to template hash `a8f9c2d1`).
4. **Edge AIOps Engine**:
   - **Streaming EWMA Anomaly Tracker**: Continuously updates exponentially weighted moving averages and running variance:
     $$\mu_t = (1 - \alpha) \mu_{t-1} + \alpha x_t$$
     $$\sigma_t^2 = (1 - \alpha) \sigma_{t-1}^2 + \alpha (x_t - \mu_t)^2$$
     When the observation $x_t$ exceeds $Z = \frac{x_t - \mu_t}{\sigma_t} > 2.8$, an edge anomaly is flagged.
   - **SLO Error Budget Burn Engine**: Tracks rapid changes in error rate percentages over sliding 60-second windows.
5. **Outbound Egress Gateway & Firewall**:
   - Acts as an internal air-gap validator.
   - Enforces an explicit blacklist of forbidden keys (`raw_log`, `message`, `payload`, `body`, `sql`, `password`).
   - If any unexpected field exists in the outbound envelope, transmission is blocked, and a local security event is raised.
   - Signs approved envelopes using HMAC-SHA256 with the tenant's pre-shared secret key.

---

## 4. Tier 2: Centralized SaaS Platform Deep Dive

The SaaS platform acts as the multi-tenant control plane, providing unified management, alerting, and cross-service intelligence across hundreds of customer environments.

### 4.1 Ingestion & Authentication
- Accepts incoming envelopes via `POST /api/v1/telemetry/egress`.
- Validates the tenant ID and verifies HMAC signatures using constant-time comparisons (`hmac.compare_digest`) to prevent timing side-channel attacks.
- Rejects unauthenticated or malformed payloads before they reach storage or processing pipelines.

### 4.2 Global AIOps & Root Cause Analysis (RCA)
- **Cross-Service Causal Correlation**: When an upstream component (e.g., database connection pool exhaustion) triggers an alert, and downstream services (e.g., API gateway, payment service) report latency spikes or 5xx errors, the Global AIOps engine merges them into a single **Correlated Incident**.
- **Tenant Health Index**: Computes real-time operational health scores (0–100%) by weighting SLI/SLO indicators across all monitored services.
- **Privacy Audit Engine**: Continuously tracks the ratio of raw bytes retained locally vs. metadata bytes transferred to SaaS, generating verifiable compliance reports for auditors.

---

## 5. Formal Data Egress Contract (Strict Schema)

To guarantee that no customer data leaves the boundary, the outbound contract is strictly typed:

```json
{
  "tenant_id": "tenant-fintech-corp",
  "collector_id": "us-east-onprem-collector-01",
  "timestamp": 1732104500.23,
  "schema_version": "2.0-strict",
  "health_indicators": [
    {
      "service": "checkout-api",
      "status": "CRITICAL",
      "cpu_percent": 78.0,
      "memory_percent": 65.0,
      "p50_latency_ms": 180.0,
      "p95_latency_ms": 950.0,
      "p99_latency_ms": 2084.1,
      "requests_per_sec": 142.5,
      "error_rate_percent": 90.9,
      "active_connections": 45
    }
  ],
  "summaries": {
    "window_start": 1732104470.0,
    "window_end": 1732104500.0,
    "total_events_processed": 1420,
    "raw_bytes_retained_locally": 412900,
    "log_level_distribution": { "INFO": 1300, "ERROR": 120 },
    "error_fingerprints": { "b4a8e291c01f": 110, "9c8a17df30a2": 10 },
    "status_codes": { "200": 1300, "500": 80, "504": 40 }
  },
  "alerts": [
    {
      "alert_id": "alert-8f92b1",
      "timestamp": 1732104498.1,
      "service": "checkout-api",
      "severity": "CRITICAL",
      "rule_or_model": "Edge-EWMA-Latency-Spike",
      "title": "Statistical Latency Anomaly on checkout-api",
      "description": "p99 latency (2084.1ms) deviated by 3.82 sigma from rolling baseline.",
      "confidence": 0.99,
      "suggested_runbook": "inspect-upstream-dependencies-and-db-pool",
      "context_indicators": {
        "observed_p99_ms": 2084.1,
        "baseline_ms": 24.5,
        "z_score": 3.82,
        "error_rate_pct": 90.9
      }
    }
  ],
  "signature": "d93ef83b5467..."
}
```

---

## 6. Threat Model & Compliance Analysis

| Threat / Regulatory Concern | Traditional APM Vulnerability | Two-Tier Secure Architecture Defense |
|---|---|---|
| **Data Exfiltration via Logs** | Application developer logs full SQL queries, authorization headers, or user objects; data streamed to SaaS vendor. | **100% Mitigated**: Multi-layer regex/NER scrubbing, payload stripping, and hard egress firewall drop any raw log field. |
| **SaaS Provider Compromise / Subpoena** | Hacker or law enforcement compromises SaaS cloud; reads all tenant customer database dumps, logs, and tokens. | **100% Mitigated**: The SaaS platform has **zero raw records** to lose. Only statistical summaries and alerts exist in the SaaS database. |
| **Network Egress Firewall Breach** | Inbound ports open into customer network allow reverse tunneling or exploit vectors. | **100% Mitigated**: Local collector only initiates **outbound-only HTTPS/mTLS connections**. Zero inbound ports are opened. |
| **GDPR "Right to be Forgotten" & Cross-Border Transfer** | User identifiers in logs transferred overseas violate EU data sovereignty requirements. | **Compliant**: Raw logs never leave the region or on-prem datacenter. Only aggregated metrics and one-way hashed fingerprints egress. |
| **HIPAA PHI Protection & PCI-DSS Section 3** | Medical history and cardholder data logged in error traces. | **Compliant**: Tokenizer replaces card PANs and PHI with redacted markers before any summarization takes place. |

---

## 7. Operational Workflow for Incident Forensics (Federated Drill-Down)

When an incident is flagged in the Central SaaS Dashboard (e.g., `INC-F4821C`):
1. **Central Triage**: SRE views the correlated root cause: `postgres-db connection pool exhaustion`.
2. **Local Drilldown (When needed)**:
   - The central UI provides an authorized direct link or local CLI command:
     ```bash
     local-collector-cli query --service postgres-db --time-window "-15m" --filter "status=500"
     ```
   - SRE authenticates via their enterprise SSO / PAM inside the corporate VPN.
   - The query executes **directly against the local SQLite/DuckDB buffer inside the customer perimeter**.
   - Raw logs and debug traces are viewed by authorized personnel inside the security boundary without any bytes transiting the SaaS cloud.
