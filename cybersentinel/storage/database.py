"""SentinelDatabase — SQLite storage for scan history and findings."""

import sqlite3
import json
import threading
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any


class SentinelDatabase:
    """SQLite database for storing scan history, findings, and metadata.

    Thread-safe storage with context managers for reliable connection handling.
    """

    def __init__(self, db_path: str = "sentinel.db"):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Get a database connection with automatic cleanup.

        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Initialize database schema if needed."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id TEXT PRIMARY KEY,
                        target TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        mode TEXT,
                        status TEXT DEFAULT 'completed',
                        findings_count INTEGER DEFAULT 0,
                        report_path TEXT,
                        metadata TEXT
                    )
                """)

                # Findings table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        component TEXT,
                        cve_ids TEXT,
                        cwe_ids TEXT,
                        cvss_score REAL,
                        epss_score REAL,
                        cisa_kev INTEGER DEFAULT 0,
                        mitre_techniques TEXT,
                        agent_source TEXT,
                        status TEXT DEFAULT 'open',
                        confidence TEXT DEFAULT 'high',
                        full_data TEXT NOT NULL,
                        FOREIGN KEY(scan_id) REFERENCES scans(id)
                    )
                """)

                # Baselines table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        id TEXT PRIMARY KEY,
                        target TEXT NOT NULL UNIQUE,
                        scan_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(scan_id) REFERENCES scans(id)
                    )
                """)

                # Annotations table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS annotations (
                        id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL,
                        text TEXT NOT NULL,
                        author TEXT,
                        timestamp TEXT NOT NULL,
                        priority TEXT,
                        tags TEXT,
                        FOREIGN KEY(finding_id) REFERENCES findings(id)
                    )
                """)

                # Audit log table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        data TEXT,
                        FOREIGN KEY(scan_id) REFERENCES scans(id)
                    )
                """)

                # Create indices for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_annotations_finding ON annotations(finding_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id)")

    def save_scan(self, scan_metadata: Dict[str, Any], findings: List) -> str:
        """Save a scan and its findings to the database.

        Args:
            scan_metadata: Dict with target, timestamp, mode, status, etc
            findings: List of Finding objects or dicts

        Returns:
            Scan ID
        """
        with self._lock:
            scan_id = scan_metadata.get('id', self._generate_id('scan'))
            target = scan_metadata.get('target', 'unknown')
            timestamp = scan_metadata.get('timestamp', datetime.now().isoformat())
            mode = scan_metadata.get('mode', 'auto')
            status = scan_metadata.get('status', 'completed')

            # Convert findings to dicts
            findings_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Save scan
                cursor.execute("""
                    INSERT OR REPLACE INTO scans (id, target, timestamp, mode, status, findings_count, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    target,
                    timestamp,
                    mode,
                    status,
                    len(findings_data),
                    json.dumps(scan_metadata)
                ))

                # Save findings
                for i, finding in enumerate(findings_data):
                    finding_id = f"{scan_id}_finding_{i}"

                    cursor.execute("""
                        INSERT OR REPLACE INTO findings
                        (id, scan_id, title, severity, component, cve_ids, cwe_ids,
                         cvss_score, epss_score, cisa_kev, mitre_techniques,
                         agent_source, status, confidence, full_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        finding_id,
                        scan_id,
                        finding.get('title', ''),
                        finding.get('severity', 'informational'),
                        finding.get('affected_component', ''),
                        json.dumps(finding.get('cve_ids', [])),
                        json.dumps(finding.get('cwe_ids', [])),
                        finding.get('cvss_score'),
                        finding.get('epss_score'),
                        int(finding.get('cisa_kev', False)),
                        json.dumps(finding.get('mitre_techniques', [])),
                        finding.get('agent_source', ''),
                        finding.get('status', 'open'),
                        finding.get('confidence', 'high'),
                        json.dumps(finding)
                    ))

        return scan_id

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a specific scan by ID.

        Args:
            scan_id: Scan ID

        Returns:
            Scan dict with findings, or None if not found
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Get scan metadata
                cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
                scan_row = cursor.fetchone()
                if not scan_row:
                    return None

                scan_dict = dict(scan_row)
                scan_dict['metadata'] = json.loads(scan_dict.get('metadata', '{}'))

                # Get findings
                cursor.execute("SELECT full_data FROM findings WHERE scan_id = ?", (scan_id,))
                findings = [json.loads(row['full_data']) for row in cursor.fetchall()]
                scan_dict['findings'] = findings

                return scan_dict

    def get_scans_for_target(self, target: str, limit: int = 10) -> List[Dict]:
        """Get all scans for a target, newest first.

        Args:
            target: Target name
            limit: Maximum number of scans to return

        Returns:
            List of scan dicts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT * FROM scans WHERE target = ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (target, limit))

                scans = []
                for row in cursor.fetchall():
                    scan_dict = dict(row)
                    scan_dict['metadata'] = json.loads(scan_dict.get('metadata', '{}'))
                    scans.append(scan_dict)

                return scans

    def get_baseline(self, target: str) -> Optional[str]:
        """Get the baseline scan ID for a target.

        Args:
            target: Target name

        Returns:
            Baseline scan ID, or None if not set
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    "SELECT scan_id FROM baselines WHERE target = ?",
                    (target,)
                )
                row = cursor.fetchone()
                return row['scan_id'] if row else None

    def set_baseline(self, target: str, scan_id: str):
        """Set or update the baseline scan for a target.

        Args:
            target: Target name
            scan_id: Scan ID to use as baseline
        """
        with self._lock:
            baseline_id = self._generate_id('baseline')

            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT OR REPLACE INTO baselines (id, target, scan_id, created_at)
                    VALUES (?, ?, ?, ?)
                """, (baseline_id, target, scan_id, datetime.now().isoformat()))

    def add_annotation(
        self,
        finding_id: str,
        text: str,
        author: str,
        priority: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """Add annotation to a finding.

        Args:
            finding_id: Finding ID
            text: Annotation text
            author: Author name
            priority: Optional priority (critical, high, medium, low, info)
            tags: Optional list of tags

        Returns:
            Annotation ID
        """
        with self._lock:
            annotation_id = self._generate_id('annotation')

            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    INSERT INTO annotations (id, finding_id, text, author, timestamp, priority, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    annotation_id,
                    finding_id,
                    text,
                    author,
                    datetime.now().isoformat(),
                    priority,
                    json.dumps(tags or [])
                ))

        return annotation_id

    def get_annotations(self, finding_id: str) -> List[Dict]:
        """Get all annotations for a finding.

        Args:
            finding_id: Finding ID

        Returns:
            List of annotation dicts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute(
                    "SELECT * FROM annotations WHERE finding_id = ? ORDER BY timestamp DESC",
                    (finding_id,)
                )

                annotations = []
                for row in cursor.fetchall():
                    ann_dict = dict(row)
                    ann_dict['tags'] = json.loads(ann_dict.get('tags', '[]'))
                    annotations.append(ann_dict)

                return annotations

    def save_audit_log(self, scan_id: str, events: List[Dict]):
        """Save audit log events for a scan.

        Args:
            scan_id: Scan ID
            events: List of event dicts (event_type, data, etc)
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                for event in events:
                    cursor.execute("""
                        INSERT INTO audit_log (scan_id, timestamp, event_type, data)
                        VALUES (?, ?, ?, ?)
                    """, (
                        scan_id,
                        datetime.now().isoformat(),
                        event.get('event_type', 'unknown'),
                        json.dumps(event.get('data', {}))
                    ))

    def search_findings(self, query: str, limit: int = 50) -> List[Dict]:
        """Search findings by title, component, or description.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of matching finding dicts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Parse query for finding data
                query_pattern = f"%{query}%"

                cursor.execute("""
                    SELECT full_data FROM findings
                    WHERE title LIKE ? OR component LIKE ?
                    LIMIT ?
                """, (query_pattern, query_pattern, limit))

                findings = []
                for row in cursor.fetchall():
                    findings.append(json.loads(row['full_data']))

                return findings

    def _generate_id(self, prefix: str) -> str:
        """Generate a unique ID with given prefix.

        Args:
            prefix: ID prefix

        Returns:
            Unique ID string
        """
        import uuid
        return f"{prefix}_{uuid.uuid4().hex[:12]}"
