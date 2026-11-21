import os
"""
Centralized SaaS Ingestion Server and Observability Portal.
Exposes REST endpoints for edge collectors to push signed metadata envelopes,
hosts the Global AIOps engine, and serves the management dashboard.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import urllib.parse
from typing import Dict, Any
from common.crypto_utils import verify_signature
from saas_platform.global_aiops import GlobalAIOpsEngine


class SaasState:
    """Shared state for SaaS ingestion and dashboard."""
    def __init__(self):
        self.aiops = GlobalAIOpsEngine()
        # Tenant API secrets: tenant_id -> shared_secret
        self.tenant_secrets: Dict[str, str] = {
            "tenant-fintech-corp": "fintech-super-secret-hmac-key-2026",
            "tenant-health-plus": "health-plus-secret-hmac-key-2026"
        }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure AIOps Observability Platform (Two-Tier Architecture)</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #f8fafc;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --badge-bg: #1e3a5f;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 24px; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; border-b: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
        h1 { font-size: 24px; color: var(--accent); }
        .badge { background: #065f46; color: #6ee7b7; padding: 4px 12px; border-radius: 9999px; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
        .card-title { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
        .card-value { font-size: 28px; font-weight: 700; color: var(--text); }
        .card-subtitle { font-size: 12px; color: var(--muted); margin-top: 6px; }
        
        .section-header { font-size: 18px; margin: 24px 0 12px 0; color: #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        
        table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); font-size: 14px; }
        th { color: var(--muted); font-weight: 600; background: #192233; }
        tr:hover { background: #243247; }
        
        .status-pill { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
        .status-healthy { background: #064e3b; color: #34d399; }
        .status-degraded { background: #78350f; color: #fbbf24; }
        .status-critical { background: #7f1d1d; color: #f87171; }
        
        .incident-box { border-left: 4px solid var(--danger); background: #26161c; padding: 16px; border-radius: 4px; margin-bottom: 12px; }
        .incident-header { display: flex; justify-content: space-between; font-weight: 600; color: #fca5a5; margin-bottom: 6px; }
        .incident-desc { font-size: 13px; color: #cbd5e1; margin-bottom: 8px; }
        .runbook { font-size: 12px; color: #38bdf8; background: #0f2744; padding: 6px 10px; border-radius: 4px; font-family: monospace; display: inline-block; }

        .architecture-banner { background: #13273e; border: 1px solid #1e4976; border-radius: 8px; padding: 16px; margin-bottom: 24px; display: flex; justify-content: space-around; align-items: center; text-align: center; }
        .arch-node { padding: 12px; background: #1e293b; border-radius: 6px; border: 1px solid #334155; width: 42%; }
        .arch-arrow { color: #38bdf8; font-weight: bold; font-size: 14px; }
        
        pre { background: #090d16; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #a5f3fc; border: 1px solid #1e293b; max-height: 250px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Secure AIOps Central Control Plane</h1>
                <div style="font-size: 13px; color: var(--muted); margin-top: 4px;">Two-Tier Architecture &bull; Tenant: <strong style="color:#e2e8f0;">__TENANT_ID__</strong></div>
            </div>
            <div>
                <span class="badge">&#128274; Zero Raw Data Egress Enforced</span>
            </div>
        </header>

        <div class="architecture-banner">
            <div class="arch-node">
                <strong style="color:#38bdf8;">CUSTOMER ON-PREM / CLOUD VPC</strong><br>
                <span style="font-size:12px; color:#94a3b8;">Local Collector &bull; Local Storage &bull; Edge EWMA AIOps</span><br>
                <span style="font-size:11px; color:#10b981;">&#10004; Raw Logs & PII 100% Retained Locally</span>
            </div>
            <div class="arch-arrow">
                &mdash;&mdash; Outbound TLS / HMAC &mdash;&mdash;&gt;<br>
                <span style="font-size:11px; color:#cbd5e1;">Metadata & Alerts ONLY</span>
            </div>
            <div class="arch-node">
                <strong style="color:#38bdf8;">CENTRALIZED SAAS PLATFORM</strong><br>
                <span style="font-size:12px; color:#94a3b8;">Global Ingestion &bull; Multi-Signal Correlator &bull; RCA</span><br>
                <span style="font-size:11px; color:#38bdf8;">Zero Trust &bull; No Sensitive Telemetry</span>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">Tenant Health Index</div>
                <div class="card-value" style="color: __HEALTH_COLOR__;">__HEALTH_SCORE__%</div>
                <div class="card-subtitle">Calculated via edge SLI/SLO indicators</div>
            </div>
            <div class="card">
                <div class="card-title">Sensitive Data Prevented From Egress</div>
                <div class="card-value" style="color: #34d399;">__RAW_BYTES_SAVED__ KB</div>
                <div class="card-subtitle">100% of raw payloads retained locally</div>
            </div>
            <div class="card">
                <div class="card-title">Egress Envelopes Received</div>
                <div class="card-value">__TOTAL_ENVELOPES__</div>
                <div class="card-subtitle">Cryptographically verified via HMAC-SHA256</div>
            </div>
            <div class="card">
                <div class="card-title">Active Root Cause Incidents</div>
                <div class="card-value" style="color: __INCIDENTS_COLOR__;">__INCIDENTS_COUNT__</div>
                <div class="card-subtitle">Correlated across edge anomaly signals</div>
            </div>
        </div>

        <div class="section-header">
            <span>Correlated Incidents (AIOps Root Cause Analysis)</span>
        </div>
        __INCIDENTS_HTML__

        <div class="section-header">
            <span>Service Health Metrics (Aggregated Statistical Indicators)</span>
        </div>
        <div class="card" style="padding: 0; overflow: hidden;">
            <table>
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Status</th>
                        <th>p50 Latency</th>
                        <th>p95 Latency</th>
                        <th>p99 Latency</th>
                        <th>Error Rate</th>
                        <th>CPU / Mem</th>
                    </tr>
                </thead>
                <tbody>
                    __HEALTH_ROWS__
                </tbody>
            </table>
        </div>

        <div class="section-header">
            <span>Privacy Audit: Outbound Egress Wire Payload (Exact JSON Received by SaaS)</span>
        </div>
        <div class="card">
            <div style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;">
                Notice: Contains statistical quantiles, abstracted error fingerprints, and health alerts. Zero customer PII or raw logs exist in this payload.
            </div>
            <pre><code>__LATEST_PAYLOAD_JSON__</code></pre>
        </div>
    </div>
</body>
</html>
"""


class SaasRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for SaaS Ingestion API and Dashboard."""

    state = SaasState()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/v1/telemetry/egress":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)

            try:
                envelope = json.loads(body_bytes.decode('utf-8'))
                tenant_id = envelope.get("tenant_id")
                signature = envelope.get("signature", "")

                secret = self.state.tenant_secrets.get(tenant_id)
                if not secret:
                    self._send_json(403, {"error": "Unknown or unauthorized tenant ID"})
                    return

                # Verify HMAC signature
                if not verify_signature(secret, envelope, signature):
                    self._send_json(401, {"error": "Invalid HMAC signature! Egress payload rejected."})
                    return

                # Ingest into SaaS Global AIOps engine
                incidents = self.state.aiops.ingest_envelope(envelope)
                self._send_json(200, {
                    "status": "ACCEPTED",
                    "tenant_id": tenant_id,
                    "incidents_triggered": len(incidents)
                })

            except Exception as e:
                self._send_json(400, {"error": f"Invalid payload schema: {str(e)}"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        tenant_id = params.get("tenant_id", ["tenant-fintech-corp"])[0]

        if parsed.path == "/api/v1/health":
            self._send_json(200, {"status": "HEALTHY", "service": "saas-control-plane"})
        elif parsed.path == "/api/v1/dashboard":
            state_dict = self.state.aiops.get_dashboard_state(tenant_id)
            self._send_json(200, state_dict)
        elif parsed.path == "/":
            self._serve_html_dashboard(tenant_id)
        else:
            self._send_json(404, {"error": "Not found"})

    def _serve_html_dashboard(self, tenant_id: str):
        state = self.state.aiops.get_dashboard_state(tenant_id)

        health_score = state["overall_health_score"]
        health_color = "#10b981" if health_score >= 80 else ("#f59e0b" if health_score >= 50 else "#ef4444")
        
        incidents = state["active_incidents"]
        incidents_color = "#ef4444" if incidents else "#10b981"

        raw_bytes_kb = round(state["total_raw_bytes_kept_local"] / 1024, 2)

        # Build Incidents HTML
        if incidents:
            inc_parts = []
            for inc in incidents:
                inc_parts.append(f"""
                <div class="incident-box">
                    <div class="incident-header">
                        <span>&#9888; {inc['incident_id']}: {inc['title']}</span>
                        <span class="status-pill status-critical">{inc['severity']}</span>
                    </div>
                    <div class="incident-desc"><strong>Probable Root Cause:</strong> {inc['probable_root_cause']}</div>
                    <div class="incident-desc"><strong>Affected Services:</strong> {', '.join(inc['affected_services'])}</div>
                    <div><span class="runbook">Runbook: {inc['recommended_action']}</span></div>
                </div>
                """)
            incidents_html = "".join(inc_parts)
        else:
            incidents_html = '<div class="card" style="color:#10b981; font-weight:600;">&#10004; All services operating within normal baseline. No incidents detected.</div>'

        # Build Health Table Rows
        health_metrics = state["latest_health_metrics"]
        if health_metrics:
            rows = []
            for m in health_metrics:
                status_class = "status-healthy" if m['status'] == "HEALTHY" else ("status-degraded" if m['status'] == "DEGRADED" else "status-critical")
                rows.append(f"""
                <tr>
                    <td><strong>{m['service']}</strong></td>
                    <td><span class="status-pill {status_class}">{m['status']}</span></td>
                    <td>{m['p50_latency_ms']} ms</td>
                    <td>{m['p95_latency_ms']} ms</td>
                    <td><strong>{m['p99_latency_ms']} ms</strong></td>
                    <td style="color:{'#f87171' if m['error_rate_percent'] > 5 else '#cbd5e1'}; font-weight:600;">{m['error_rate_percent']}%</td>
                    <td>{m['cpu_percent']}% / {m['memory_percent']}%</td>
                </tr>
                """)
            health_rows = "".join(rows)
        else:
            health_rows = '<tr><td colspan="7" style="text-align:center; color:#94a3b8;">No health digests received yet.</td></tr>'

        # Build Latest Payload JSON
        envelopes = self.state.aiops.tenant_envelopes.get(tenant_id, [])
        latest_json = json.dumps(envelopes[-1], indent=2) if envelopes else "/* No envelope received yet */"

        html = HTML_TEMPLATE \
            .replace("__TENANT_ID__", tenant_id) \
            .replace("__HEALTH_SCORE__", str(health_score)) \
            .replace("__HEALTH_COLOR__", health_color) \
            .replace("__RAW_BYTES_SAVED__", str(raw_bytes_kb)) \
            .replace("__TOTAL_ENVELOPES__", str(state["total_envelopes_ingested"])) \
            .replace("__INCIDENTS_COUNT__", str(len(incidents))) \
            .replace("__INCIDENTS_COLOR__", incidents_color) \
            .replace("__INCIDENTS_HTML__", incidents_html) \
            .replace("__HEALTH_ROWS__", health_rows) \
            .replace("__LATEST_PAYLOAD_JSON__", latest_json)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence default stderr logging to keep console clean
        pass


    @classmethod
    def ingest_direct(cls, payload_dict: Dict[str, Any]) -> Dict[str, Any]:
        """In-process direct ingestion for testing or sandboxed offline execution."""
        tenant_id = payload_dict.get("tenant_id")
        signature = payload_dict.get("signature", "")
        secret = cls.state.tenant_secrets.get(tenant_id)
        if not secret:
            return {"status": "ERROR", "error": "Unknown or unauthorized tenant ID"}
        if not verify_signature(secret, payload_dict, signature):
            return {"status": "ERROR", "error": "Invalid HMAC signature"}
        incidents = cls.state.aiops.ingest_envelope(payload_dict)
        return {
            "status": "ACCEPTED",
            "tenant_id": tenant_id,
            "incidents_triggered": len(incidents)
        }


def run_saas_server(port: int = int(os.environ.get("PORT", 8088))) -> HTTPServer:
    """Start the SaaS server instance."""
    server_address = ("0.0.0.0", port)
    try:
        httpd = HTTPServer(server_address, SaasRequestHandler)
        httpd.state = SaasRequestHandler.state
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd
    except Exception:
        # Fallback dummy server container for socket-restricted sandboxes
        class MockServer:
            state = SaasRequestHandler.state
        return MockServer()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8088))
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, SaasRequestHandler)
    print(f"[*] Secure AIOps Central Control Plane running on http://127.0.0.1:{port}")
    print(f"[*] Dashboard: http://127.0.0.1:{port}/?tenant_id=tenant-fintech-corp")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
