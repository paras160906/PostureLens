"""
Database persistence layer using SQLite for PostureLens scan history and runtime alerts.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = Path(__file__).parent.parent / "posturelens.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = db_path if db_path else DEFAULT_DB_PATH
    conn = sqlite3.connect(str(target_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize the SQLite database schemas."""
    conn = get_connection(db_path)
    try:
        with conn:
            # Scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    total_violations INTEGER NOT NULL,
                    scan_result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # Runtime alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runtime_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    field_path TEXT NOT NULL,
                    container_id TEXT NOT NULL,
                    pod_name TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
    finally:
        conn.close()


def save_scan(
    filename: str,
    file_type: str,
    risk_score: int,
    risk_level: str,
    total_violations: int,
    scan_result_dict: Dict[str, Any],
    db_path: Optional[Path] = None
) -> int:
    """Insert a new scan record into SQLite and return its auto-generated ID."""
    conn = get_connection(db_path)
    created_at = datetime.now(timezone.utc).isoformat()
    scan_json = json.dumps(scan_result_dict)
    
    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scans (
                    filename, file_type, risk_score, risk_level,
                    total_violations, scan_result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                filename, file_type, risk_score, risk_level,
                total_violations, scan_json, created_at
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def get_all_scans(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve summary list of past scans sorted by date descending."""
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT id, filename, file_type, risk_score, risk_level, total_violations, created_at
            FROM scans
            ORDER BY id DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieve complete scan record by ID including raw scan result JSON."""
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT id, filename, file_type, risk_score, risk_level, total_violations, scan_result_json, created_at
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        
        data = dict(row)
        data["scan_result"] = json.loads(data.pop("scan_result_json"))
        return data
    finally:
        conn.close()


def save_runtime_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    title: str,
    description: str,
    field_path: str,
    container_id: str,
    pod_name: str,
    namespace: str,
    raw_payload_dict: Dict[str, Any],
    db_path: Optional[Path] = None
) -> int:
    """Insert a normalized runtime alert into SQLite database."""
    conn = get_connection(db_path)
    created_at = datetime.now(timezone.utc).isoformat()
    raw_json = json.dumps(raw_payload_dict)

    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO runtime_alerts (
                    rule_id, rule_name, severity, title, description,
                    field_path, container_id, pod_name, namespace,
                    raw_payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id, rule_name, severity, title, description,
                field_path, container_id, pod_name, namespace,
                raw_json, created_at
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def get_runtime_alerts(limit: int = 100, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve list of ingested runtime security alerts sorted by timestamp descending."""
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT id, rule_id, rule_name, severity, title, description,
                   field_path, container_id, pod_name, namespace, created_at
            FROM runtime_alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
