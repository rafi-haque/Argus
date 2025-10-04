"""
Database storage layer for Argus scanner.

Provides persistent storage for scan results with support for:
- SQLite (single-user, file-based)
- PostgreSQL (multi-user, production-ready)

Usage:
    # SQLite
    db = ScanDatabase('sqlite:///argus.db')
    
    # PostgreSQL
    db = ScanDatabase('postgresql://user:pass@localhost/argus')
    
    # Store a scan
    scan_id = db.store_scan(target_url, findings, stats, config)
    
    # Retrieve scans
    scans = db.list_scans(limit=10)
    scan = db.get_scan(scan_id)
    
    # Trend analysis
    trend = db.get_vulnerability_trend(days=30)
    comparison = db.compare_scans(scan_id_1, scan_id_2)
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

try:
    import psycopg2
    import psycopg2.extras
    POSTGRESQL_AVAILABLE = True
except ImportError:
    POSTGRESQL_AVAILABLE = False

from argus.database.schema import SQLITE_SCHEMA, POSTGRESQL_SCHEMA

logger = logging.getLogger(__name__)


@dataclass
class ScanRecord:
    """Represents a scan record in the database."""
    id: Optional[int]
    target_url: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    status: str
    total_requests: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    config_json: Optional[str] = None
    modules_used: Optional[str] = None
    scanner_version: Optional[str] = None
    user_id: Optional[int] = None
    notes: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass
class FindingRecord:
    """Represents a finding record in the database."""
    id: Optional[int]
    scan_id: int
    type: str
    severity: str
    title: str
    description: str
    url: str
    method: str = 'GET'
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_ids: Optional[str] = None
    pci_dss_refs: Optional[str] = None
    hipaa_refs: Optional[str] = None
    remediation: Optional[str] = None
    reference_urls: Optional[str] = None
    confidence: Optional[float] = None
    false_positive: bool = False
    verified: bool = False
    created_at: Optional[datetime] = None


class ScanDatabase:
    """Database interface for storing and retrieving scan results."""
    
    def __init__(self, connection_string: str = 'sqlite:///argus.db'):
        """
        Initialize database connection.
        
        Args:
            connection_string: Database connection string
                SQLite: 'sqlite:///path/to/db.db'
                PostgreSQL: 'postgresql://user:pass@host:port/dbname'
        """
        self.connection_string = connection_string
        self.db_type = self._parse_connection_string(connection_string)
        self.connection = None
        
        if self.db_type == 'sqlite':
            self._init_sqlite()
        elif self.db_type == 'postgresql':
            self._init_postgresql()
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def _parse_connection_string(self, conn_str: str) -> str:
        """Parse connection string to determine database type."""
        if conn_str.startswith('sqlite:///'):
            return 'sqlite'
        elif conn_str.startswith('postgresql://'):
            if not POSTGRESQL_AVAILABLE:
                raise ImportError("PostgreSQL support requires psycopg2. Install with: pip install psycopg2-binary")
            return 'postgresql'
        else:
            raise ValueError(f"Invalid connection string: {conn_str}")
    
    def _init_sqlite(self):
        """Initialize SQLite database."""
        db_path = self.connection_string.replace('sqlite:///', '')
        db_file = Path(db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        
        # Execute schema
        cursor = self.connection.cursor()
        cursor.executescript(SQLITE_SCHEMA)
        self.connection.commit()
        
        logger.info(f"SQLite database initialized: {db_path}")
    
    def _init_postgresql(self):
        """Initialize PostgreSQL database."""
        # Extract connection parameters
        conn_str = self.connection_string.replace('postgresql://', '')
        
        self.connection = psycopg2.connect(self.connection_string)
        self.connection.autocommit = False
        
        # Execute schema
        cursor = self.connection.cursor()
        cursor.execute(POSTGRESQL_SCHEMA)
        self.connection.commit()
        
        logger.info("PostgreSQL database initialized")
    
    def store_scan(
        self,
        target_url: str,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
        status: str = 'completed',
        notes: Optional[str] = None
    ) -> int:
        """
        Store a complete scan result in the database.
        
        Args:
            target_url: The target URL that was scanned
            findings: List of vulnerability findings
            stats: Scan statistics (start_time, end_time, requests, etc.)
            config: Scan configuration (optional)
            status: Scan status ('completed', 'failed', 'cancelled')
            notes: Optional notes about the scan
        
        Returns:
            scan_id: The ID of the stored scan
        """
        cursor = self.connection.cursor()
        
        try:
            # Calculate statistics
            severity_counts = self._calculate_severity_counts(findings)
            
            # Prepare scan record
            start_time = stats.get('start_time', datetime.now())
            end_time = stats.get('end_time', datetime.now())
            
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time)
            
            duration = (end_time - start_time).total_seconds()
            
            # Insert scan record
            scan_query = """
                INSERT INTO scans (
                    target_url, start_time, end_time, duration_seconds, status,
                    total_requests, total_findings,
                    critical_count, high_count, medium_count, low_count, info_count,
                    config_json, modules_used, scanner_version, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """ if self.db_type == 'sqlite' else """
                INSERT INTO scans (
                    target_url, start_time, end_time, duration_seconds, status,
                    total_requests, total_findings,
                    critical_count, high_count, medium_count, low_count, info_count,
                    config_json, modules_used, scanner_version, notes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """
            
            config_json = json.dumps(config) if config else None
            modules_used = ','.join(config.get('modules', [])) if config and 'modules' in config else None
            
            cursor.execute(scan_query, (
                target_url, start_time, end_time, duration, status,
                stats.get('total_requests', 0), len(findings),
                severity_counts['critical'], severity_counts['high'],
                severity_counts['medium'], severity_counts['low'],
                severity_counts['info'],
                config_json, modules_used, stats.get('version', '1.0'), notes
            ))
            
            # Get scan ID
            if self.db_type == 'sqlite':
                scan_id = cursor.lastrowid
            else:
                scan_id = cursor.fetchone()[0]
            
            # Insert findings
            self._store_findings(cursor, scan_id, findings)
            
            # Update target record
            self._update_target(cursor, target_url, len(findings), severity_counts)
            
            self.connection.commit()
            logger.info(f"Stored scan #{scan_id} for {target_url} with {len(findings)} findings")
            
            return scan_id
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Failed to store scan: {e}")
            raise
    
    def _calculate_severity_counts(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate count of findings by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _store_findings(self, cursor, scan_id: int, findings: List[Dict[str, Any]]):
        """Store findings for a scan."""
        finding_query = """
            INSERT INTO findings (
                scan_id, type, severity, title, description, url, method, parameter,
                payload, evidence, request_data, response_data,
                owasp_category, cwe_ids, pci_dss_refs, hipaa_refs,
                remediation, reference_urls, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """ if self.db_type == 'sqlite' else """
            INSERT INTO findings (
                scan_id, type, severity, title, description, url, method, parameter,
                payload, evidence, request_data, response_data,
                owasp_category, cwe_ids, pci_dss_refs, hipaa_refs,
                remediation, reference_urls, confidence
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        for finding in findings:
            # Extract compliance data if available
            compliance = finding.get('compliance', {})
            owasp_cat = None
            cwe_ids = None
            pci_refs = None
            hipaa_refs = None
            
            if compliance:
                if 'owasp' in compliance:
                    owasp_cat = compliance['owasp'].get('id')
                if 'cwe' in compliance:
                    cwe_ids = ','.join([f"CWE-{cwe}" for cwe in compliance['cwe'].get('ids', [])])
                if 'pci_dss' in compliance:
                    pci_refs = ','.join(compliance['pci_dss'].get('requirements', []))
                if 'hipaa' in compliance:
                    hipaa_refs = ','.join(compliance['hipaa'].get('controls', []))
            
            # Serialize complex data
            request_data = json.dumps(finding.get('request')) if finding.get('request') else None
            response_data = json.dumps(finding.get('response')) if finding.get('response') else None
            references_json = json.dumps(finding.get('references', []))
            
            cursor.execute(finding_query, (
                scan_id,
                finding.get('type', 'unknown'),
                finding.get('severity', 'info'),
                finding.get('title', ''),
                finding.get('description', ''),
                finding.get('url', ''),
                finding.get('method', 'GET'),
                finding.get('parameter'),
                finding.get('payload'),
                finding.get('evidence'),
                request_data,
                response_data,
                owasp_cat,
                cwe_ids,
                pci_refs,
                hipaa_refs,
                finding.get('remediation'),
                references_json,
                finding.get('confidence')
            ))
    
    def _update_target(self, cursor, target_url: str, finding_count: int, severity_counts: Dict[str, int]):
        """Update or create target record."""
        # Check if target exists
        cursor.execute("SELECT id, scan_count FROM targets WHERE url = ?", (target_url,)) \
            if self.db_type == 'sqlite' else \
            cursor.execute("SELECT id, scan_count FROM targets WHERE url = %s", (target_url,))
        
        row = cursor.fetchone()
        
        if row:
            # Update existing target
            if self.db_type == 'sqlite':
                target_id, scan_count = row
            else:
                target_id, scan_count = row
            
            update_query = """
                UPDATE targets SET
                    last_scanned = ?,
                    scan_count = ?,
                    total_findings = total_findings + ?,
                    critical_findings = critical_findings + ?,
                    high_findings = high_findings + ?
                WHERE id = ?
            """ if self.db_type == 'sqlite' else """
                UPDATE targets SET
                    last_scanned = %s,
                    scan_count = %s,
                    total_findings = total_findings + %s,
                    critical_findings = critical_findings + %s,
                    high_findings = high_findings + %s
                WHERE id = %s
            """
            
            cursor.execute(update_query, (
                datetime.now(), scan_count + 1, finding_count,
                severity_counts['critical'], severity_counts['high'],
                target_id
            ))
        else:
            # Insert new target
            insert_query = """
                INSERT INTO targets (
                    url, last_scanned, scan_count, total_findings,
                    critical_findings, high_findings
                ) VALUES (?, ?, ?, ?, ?, ?)
            """ if self.db_type == 'sqlite' else """
                INSERT INTO targets (
                    url, last_scanned, scan_count, total_findings,
                    critical_findings, high_findings
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            cursor.execute(insert_query, (
                target_url, datetime.now(), 1, finding_count,
                severity_counts['critical'], severity_counts['high']
            ))
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan by ID with all its findings.
        
        Args:
            scan_id: The scan ID
        
        Returns:
            Dictionary containing scan metadata and findings, or None if not found
        """
        cursor = self.connection.cursor()
        
        # Get scan metadata
        scan_query = "SELECT * FROM scans WHERE id = ?" if self.db_type == 'sqlite' else \
                     "SELECT * FROM scans WHERE id = %s"
        cursor.execute(scan_query, (scan_id,))
        scan_row = cursor.fetchone()
        
        if not scan_row:
            return None
        
        # Convert to dict
        if self.db_type == 'sqlite':
            scan = dict(scan_row)
        else:
            columns = [desc[0] for desc in cursor.description]
            scan = dict(zip(columns, scan_row))
        
        # Get findings
        findings_query = "SELECT * FROM findings WHERE scan_id = ?" if self.db_type == 'sqlite' else \
                        "SELECT * FROM findings WHERE scan_id = %s"
        cursor.execute(findings_query, (scan_id,))
        
        findings = []
        for finding_row in cursor.fetchall():
            if self.db_type == 'sqlite':
                finding = dict(finding_row)
            else:
                columns = [desc[0] for desc in cursor.description]
                finding = dict(zip(columns, finding_row))
            findings.append(finding)
        
        scan['findings'] = findings
        return scan
    
    def list_scans(
        self,
        target_url: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List scans with optional filtering.
        
        Args:
            target_url: Filter by target URL (optional)
            limit: Maximum number of scans to return
            offset: Offset for pagination
            status: Filter by status (optional)
        
        Returns:
            List of scan records (without detailed findings)
        """
        cursor = self.connection.cursor()
        
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if target_url:
            query += " AND target_url = ?" if self.db_type == 'sqlite' else " AND target_url = %s"
            params.append(target_url)
        
        if status:
            query += " AND status = ?" if self.db_type == 'sqlite' else " AND status = %s"
            params.append(status)
        
        query += " ORDER BY start_time DESC LIMIT ? OFFSET ?" if self.db_type == 'sqlite' else \
                " ORDER BY start_time DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        scans = []
        for row in cursor.fetchall():
            if self.db_type == 'sqlite':
                scan = dict(row)
            else:
                columns = [desc[0] for desc in cursor.description]
                scan = dict(zip(columns, row))
            scans.append(scan)
        
        return scans
    
    def get_vulnerability_trend(
        self,
        target_url: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get vulnerability trend over time.
        
        Args:
            target_url: Filter by target URL (optional)
            days: Number of days to analyze
        
        Returns:
            Dictionary with trend data including:
            - daily_counts: List of {date, total, critical, high, medium, low}
            - summary: Overall statistics
        """
        cursor = self.connection.cursor()
        
        since_date = datetime.now() - timedelta(days=days)
        
        query = """
            SELECT 
                DATE(start_time) as scan_date,
                COUNT(*) as scan_count,
                SUM(total_findings) as total_findings,
                SUM(critical_count) as critical,
                SUM(high_count) as high,
                SUM(medium_count) as medium,
                SUM(low_count) as low
            FROM scans
            WHERE start_time >= ?
        """ if self.db_type == 'sqlite' else """
            SELECT 
                DATE(start_time) as scan_date,
                COUNT(*) as scan_count,
                SUM(total_findings) as total_findings,
                SUM(critical_count) as critical,
                SUM(high_count) as high,
                SUM(medium_count) as medium,
                SUM(low_count) as low
            FROM scans
            WHERE start_time >= %s
        """
        
        params = [since_date]
        
        if target_url:
            query += " AND target_url = ?" if self.db_type == 'sqlite' else " AND target_url = %s"
            params.append(target_url)
        
        query += " GROUP BY DATE(start_time) ORDER BY scan_date"
        
        cursor.execute(query, params)
        
        daily_counts = []
        for row in cursor.fetchall():
            if self.db_type == 'sqlite':
                day = dict(row)
            else:
                columns = [desc[0] for desc in cursor.description]
                day = dict(zip(columns, row))
            daily_counts.append(day)
        
        # Calculate summary
        total_scans = sum(day['scan_count'] for day in daily_counts)
        total_findings = sum(day['total_findings'] or 0 for day in daily_counts)
        
        return {
            'days': days,
            'target_url': target_url,
            'daily_counts': daily_counts,
            'summary': {
                'total_scans': total_scans,
                'total_findings': total_findings,
                'avg_findings_per_scan': total_findings / total_scans if total_scans > 0 else 0
            }
        }
    
    def compare_scans(self, scan_id_1: int, scan_id_2: int) -> Dict[str, Any]:
        """
        Compare two scans to identify new, fixed, and changed vulnerabilities.
        
        Args:
            scan_id_1: ID of the older scan
            scan_id_2: ID of the newer scan
        
        Returns:
            Dictionary with:
            - new: Vulnerabilities present in scan_2 but not scan_1
            - fixed: Vulnerabilities present in scan_1 but not scan_2
            - changed: Vulnerabilities that changed severity
            - unchanged: Vulnerabilities present in both with same severity
        """
        scan_1 = self.get_scan(scan_id_1)
        scan_2 = self.get_scan(scan_id_2)
        
        if not scan_1 or not scan_2:
            raise ValueError("One or both scans not found")
        
        # Create lookup maps: (type, url, parameter) -> finding
        def make_key(finding):
            return (
                finding['type'],
                finding['url'],
                finding.get('parameter', '')
            )
        
        findings_1 = {make_key(f): f for f in scan_1['findings']}
        findings_2 = {make_key(f): f for f in scan_2['findings']}
        
        keys_1 = set(findings_1.keys())
        keys_2 = set(findings_2.keys())
        
        # Calculate differences
        new_keys = keys_2 - keys_1
        fixed_keys = keys_1 - keys_2
        common_keys = keys_1 & keys_2
        
        new = [findings_2[k] for k in new_keys]
        fixed = [findings_1[k] for k in fixed_keys]
        changed = []
        unchanged = []
        
        for key in common_keys:
            f1 = findings_1[key]
            f2 = findings_2[key]
            if f1['severity'] != f2['severity']:
                changed.append({
                    'finding': f2,
                    'old_severity': f1['severity'],
                    'new_severity': f2['severity']
                })
            else:
                unchanged.append(f2)
        
        return {
            'scan_1': {
                'id': scan_id_1,
                'target_url': scan_1['target_url'],
                'start_time': scan_1['start_time'],
                'total_findings': len(scan_1['findings'])
            },
            'scan_2': {
                'id': scan_id_2,
                'target_url': scan_2['target_url'],
                'start_time': scan_2['start_time'],
                'total_findings': len(scan_2['findings'])
            },
            'comparison': {
                'new': new,
                'fixed': fixed,
                'changed': changed,
                'unchanged': unchanged
            },
            'summary': {
                'new_count': len(new),
                'fixed_count': len(fixed),
                'changed_count': len(changed),
                'unchanged_count': len(unchanged)
            }
        }
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and all its findings.
        
        Args:
            scan_id: The scan ID to delete
        
        Returns:
            True if deleted, False if not found
        """
        cursor = self.connection.cursor()
        
        try:
            delete_query = "DELETE FROM scans WHERE id = ?" if self.db_type == 'sqlite' else \
                          "DELETE FROM scans WHERE id = %s"
            cursor.execute(delete_query, (scan_id,))
            self.connection.commit()
            
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"Deleted scan #{scan_id}")
            
            return deleted
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Failed to delete scan: {e}")
            raise
    
    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
