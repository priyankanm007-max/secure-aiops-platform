"""
Local storage engine inside customer environment.
Retains full raw telemetry locally for compliance, forensic debugging,
and local-only operator drilldowns. Raw data NEVER leaves this host.
"""

import sqlite3
import json
import time
import os
from typing import List, Dict, Any, Optional
from common.models import RawTelemetryEvent


class LocalTelemetryStore:
    """Secure local-only database for raw telemetry with automatic TTL rotation."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL,
                service TEXT,
                environment TEXT,
                event_type TEXT,
                raw_payload TEXT,
                metadata_json TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_time ON raw_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_service ON raw_events(service)")

        # Offline Egress Buffer for store-and-forward resilience and deduplication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS offline_egress_buffer (
                envelope_id TEXT PRIMARY KEY,
                envelope_hash TEXT UNIQUE,
                timestamp REAL,
                payload_json TEXT,
                retry_count INTEGER DEFAULT 0,
                created_at REAL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_buf_created ON offline_egress_buffer(created_at)")
        self.conn.commit()

    def store_event(self, event: RawTelemetryEvent):
        """Store a raw event locally."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO raw_events 
            (event_id, timestamp, service, environment, event_type, raw_payload, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.timestamp,
            event.service,
            event.environment,
            event.event_type,
            event.raw_payload,
            json.dumps(event.metadata)
        ))
        self.conn.commit()

    def get_event_count(self) -> int:
        """Total events stored locally."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM raw_events")
        return cursor.fetchone()[0]

    def get_total_raw_bytes(self) -> int:
        """Get approximate size of raw payloads stored locally."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT SUM(LENGTH(raw_payload)) FROM raw_events")
        result = cursor.fetchone()[0]
        return result if result else 0

    def query_local_raw_by_service(self, service: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Authorized local-only inspection (operators within internal perimeter)."""
        return self.query_local_raw(service=service, limit=limit)

    def query_local_raw(self, service: Optional[str] = None, limit: int = 20, filter_text: Optional[str] = None) -> List[Dict[str, Any]]:
        """Authorized local-only inspection with flexible filtering."""
        cursor = self.conn.cursor()
        query = "SELECT event_id, timestamp, service, environment, event_type, raw_payload, metadata_json FROM raw_events"
        params = []
        conditions = []

        if service:
            conditions.append("service = ?")
            params.append(service)
        if filter_text:
            conditions.append("raw_payload LIKE ?")
            params.append(f"%{filter_text}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [
            {
                "event_id": r[0],
                "timestamp": r[1],
                "service": r[2],
                "environment": r[3],
                "event_type": r[4],
                "raw_payload": r[5],
                "metadata": json.loads(r[6]) if r[6] else {}
            }
            for r in rows
        ]

    def buffer_envelope(self, envelope_id: str, envelope_hash: str, timestamp: float, payload_dict: Dict[str, Any]) -> bool:
        """Store an egress envelope locally when SaaS is offline.
        
        Uses INSERT OR IGNORE on envelope_hash for deduplication.
        Returns True if newly buffered, False if already present (duplicate).
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO offline_egress_buffer
            (envelope_id, envelope_hash, timestamp, payload_json, retry_count, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
        """, (
            envelope_id,
            envelope_hash,
            timestamp,
            json.dumps(payload_dict),
            time.time()
        ))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_buffered_envelopes(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve pending offline envelopes ordered by creation time."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT envelope_id, envelope_hash, timestamp, payload_json, retry_count, created_at
            FROM offline_egress_buffer
            ORDER BY created_at ASC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [
            {
                "envelope_id": r[0],
                "envelope_hash": r[1],
                "timestamp": r[2],
                "payload": json.loads(r[3]),
                "retry_count": r[4],
                "created_at": r[5]
            }
            for r in rows
        ]

    def increment_retry(self, envelope_id: str):
        """Increment retry attempt counter for a buffered envelope."""
        cursor = self.conn.cursor()
        cursor.execute("UPDATE offline_egress_buffer SET retry_count = retry_count + 1 WHERE envelope_id = ?", (envelope_id,))
        self.conn.commit()

    def delete_buffered_envelope(self, envelope_id: str):
        """Remove successfully transmitted envelope from offline buffer."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM offline_egress_buffer WHERE envelope_id = ?", (envelope_id,))
        self.conn.commit()

    def get_buffered_count(self) -> int:
        """Return number of envelopes waiting in offline buffer."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM offline_egress_buffer")
        return cursor.fetchone()[0]

    def purge_expired_records(self, retention_seconds: float):
        """TTL cleanup: prune records older than retention window."""
        cutoff = time.time() - retention_seconds
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM raw_events WHERE timestamp < ?", (cutoff,))
        self.conn.commit()

    def close(self):
        self.conn.close()
