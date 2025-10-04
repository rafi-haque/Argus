# Argus Database Layer User Guide

## Overview

The Argus Database Layer provides persistent storage for scan results, enabling:

- **Historical Analysis**: Track vulnerability trends over time
- **Scan Comparison**: Compare scans to identify new/fixed vulnerabilities
- **Scheduled Scans**: Automate recurring security scans
- **Multi-Database Support**: SQLite (single-user) or PostgreSQL (multi-user)
- **CLI Management**: Comprehensive command-line interface for database operations

## Quick Start

### Basic Usage

```python
from argus.database import ScanDatabase

# Create database connection
db = ScanDatabase('sqlite:///argus.db')

# Store a scan result
scan_id = db.store_scan(
    target_url='https://example.com',
    findings=[
        {
            'type': 'xss',
            'severity': 'high',
            'title': 'Cross-Site Scripting',
            'description': 'XSS vulnerability detected',
            'url': 'https://example.com/page',
            'parameter': 'q',
            'payload': '<script>alert(1)</script>',
            'remediation': 'Sanitize user input'
        }
    ],
    stats={
        'start_time': datetime.now(),
        'end_time': datetime.now(),
        'total_requests': 100,
        'version': '1.0'
    },
    config={'modules': ['xss', 'sqli']},
    status='completed'
)

print(f"Stored scan #{scan_id}")

# Retrieve scan
scan = db.get_scan(scan_id)
print(f"Found {scan['total_findings']} vulnerabilities")

# List recent scans
scans = db.list_scans(limit=10)
for s in scans:
    print(f"#{s['id']}: {s['target_url']} - {s['total_findings']} findings")

db.close()
```

### Using the CLI

The `argus_db.py` CLI tool provides easy database management:

```bash
# List recent scans
python argus_db.py --db argus.db list --limit 10

# View scan details
python argus_db.py --db argus.db show 42

# Analyze vulnerability trend
python argus_db.py --db argus.db trend --days 30

# Compare two scans
python argus_db.py --db argus.db compare 10 20

# Export scan to JSON
python argus_db.py --db argus.db export 42 --output scan_42.json
```

## Installation

### Requirements

```bash
# Core database functionality (SQLite)
pip install pyyaml

# Optional: PostgreSQL support
pip install psycopg2-binary

# Optional: Scheduled scans
pip install apscheduler
```

### Database Setup

**SQLite (recommended for single-user):**

```python
from argus.database import ScanDatabase

# Database file will be created automatically
db = ScanDatabase('sqlite:///argus.db')
```

**PostgreSQL (recommended for multi-user):**

```bash
# Create database
createdb argus

# Connect from Python
```

```python
db = ScanDatabase('postgresql://user:password@localhost/argus')
```

## Core Features

### 1. Scan Storage

Store complete scan results with metadata:

```python
scan_id = db.store_scan(
    target_url='https://example.com',
    findings=findings_list,
    stats={
        'start_time': scan_start,
        'end_time': scan_end,
        'total_requests': 150,
        'version': '1.0'
    },
    config={
        'modules': ['xss', 'sqli', 'csrf'],
        'depth': 3,
        'timeout': 10
    },
    status='completed',  # 'completed', 'failed', 'cancelled'
    notes='Weekly security scan'
)
```

**Finding Structure:**

```python
finding = {
    # Core vulnerability info
    'type': 'sqli',                    # Vulnerability type
    'severity': 'critical',            # critical, high, medium, low, info
    'title': 'SQL Injection',
    'description': 'Detailed description...',
    
    # Location
    'url': 'https://example.com/page',
    'method': 'POST',                  # HTTP method
    'parameter': 'username',           # Vulnerable parameter
    
    # Evidence
    'payload': "' OR 1=1--",           # Attack payload used
    'evidence': 'SQL error in response',
    'request': {...},                  # Full request data (optional)
    'response': {...},                 # Full response data (optional)
    
    # Compliance (auto-populated if compliance mapper used)
    'compliance': {
        'owasp': {'id': 'A03:2021', 'category': 'Injection'},
        'cwe': {'ids': [89]},
        'pci_dss': {'requirements': ['6.2.4']},
        'hipaa': {'controls': ['§164.308(a)(1)(ii)(D)']}
    },
    
    # Remediation
    'remediation': 'Use parameterized queries',
    'references': ['https://owasp.org/...'],
    
    # Metadata
    'confidence': 0.95,                # 0.0 to 1.0
    'false_positive': False,
    'verified': True
}
```

### 2. Scan Retrieval

**Get Specific Scan:**

```python
scan = db.get_scan(scan_id)

# Access scan metadata
print(f"Target: {scan['target_url']}")
print(f"Duration: {scan['duration_seconds']} seconds")
print(f"Findings: {scan['total_findings']}")
print(f"Critical: {scan['critical_count']}")

# Access findings
for finding in scan['findings']:
    print(f"[{finding['severity']}] {finding['title']}")
    print(f"  URL: {finding['url']}")
```

**List Scans with Filtering:**

```python
# Recent scans
scans = db.list_scans(limit=20)

# Filter by target
scans = db.list_scans(target_url='https://example.com', limit=10)

# Filter by status
scans = db.list_scans(status='completed', limit=10)

# Pagination
scans = db.list_scans(limit=20, offset=40)
```

### 3. Trend Analysis

Analyze vulnerability trends over time:

```python
# Get 30-day trend
trend = db.get_vulnerability_trend(days=30)

print(f"Total Scans: {trend['summary']['total_scans']}")
print(f"Total Findings: {trend['summary']['total_findings']}")
print(f"Avg Per Scan: {trend['summary']['avg_findings_per_scan']:.1f}")

# Daily breakdown
for day in trend['daily_counts']:
    print(f"{day['scan_date']}: {day['total_findings']} findings")
    print(f"  Critical: {day['critical']}, High: {day['high']}")
```

**Trend for Specific Target:**

```python
trend = db.get_vulnerability_trend(
    target_url='https://example.com',
    days=30
)
```

**CLI Usage:**

```bash
# 30-day trend
python argus_db.py trend --days 30

# Trend for specific target
python argus_db.py trend --days 30 --target https://example.com
```

### 4. Scan Comparison

Compare two scans to identify changes:

```python
comparison = db.compare_scans(scan_id_1, scan_id_2)

# Summary
summary = comparison['summary']
print(f"New: {summary['new_count']}")
print(f"Fixed: {summary['fixed_count']}")
print(f"Changed: {summary['changed_count']}")

# New vulnerabilities
for finding in comparison['comparison']['new']:
    print(f"NEW: [{finding['severity']}] {finding['title']}")
    print(f"     {finding['url']}")

# Fixed vulnerabilities
for finding in comparison['comparison']['fixed']:
    print(f"FIXED: [{finding['severity']}] {finding['title']}")

# Changed severity
for item in comparison['comparison']['changed']:
    finding = item['finding']
    print(f"CHANGED: {finding['title']}")
    print(f"         {item['old_severity']} → {item['new_severity']}")
```

**CLI Usage:**

```bash
python argus_db.py compare 10 20
```

### 5. Scheduled Scans

Automate recurring scans:

```python
from argus.database import ScanScheduler

scheduler = ScanScheduler(db, scan_function=run_scan)

# Add daily scan
job_id = scheduler.add_job(
    name='Daily Security Scan',
    target_url='https://example.com',
    schedule_type='daily',
    schedule_value='02:00',        # Run at 2:00 AM
    modules=['xss', 'sqli'],
    notify_on_new_findings=True,
    notification_email='security@example.com'
)

# Start scheduler
scheduler.start()

# List jobs
jobs = scheduler.list_jobs()
for job in jobs:
    print(f"#{job['id']}: {job['name']}")
    print(f"  Next run: {job['next_run']}")

# Pause job
scheduler.pause_job(job_id)

# Resume job
scheduler.resume_job(job_id)

# Stop scheduler
scheduler.stop()
```

**Schedule Types:**

| Type     | Value Format          | Example                  |
|----------|-----------------------|--------------------------|
| once     | ISO datetime          | `'2025-12-31 23:59'`     |
| daily    | HH:MM                 | `'02:00'`                |
| weekly   | DAY HH:MM             | `'MON 14:00'`            |
| monthly  | DD HH:MM              | `'15 14:00'` (15th)      |
| cron     | Cron expression       | `'0 2 * * 1'` (Mon 2AM)  |

**CLI Usage:**

```bash
# Add daily scan
python argus_db.py schedule add \
  --name "Daily Scan" \
  --url https://example.com \
  --schedule daily \
  --time 02:00 \
  --modules xss,sqli

# List scheduled jobs
python argus_db.py schedule list

# Show job details
python argus_db.py schedule show 1

# Pause job
python argus_db.py schedule pause 1

# Resume job
python argus_db.py schedule resume 1

# Delete job
python argus_db.py schedule delete 1
```

## CLI Reference

### List Scans

```bash
python argus_db.py list [OPTIONS]

Options:
  --limit N           Maximum number of scans (default: 20)
  --target URL        Filter by target URL
  --status STATUS     Filter by status (completed, failed, cancelled)
```

### Show Scan

```bash
python argus_db.py show SCAN_ID [OPTIONS]

Options:
  --no-findings       Don't show detailed findings
```

### Trend Analysis

```bash
python argus_db.py trend [OPTIONS]

Options:
  --days N            Number of days to analyze (default: 30)
  --target URL        Filter by target URL
```

### Compare Scans

```bash
python argus_db.py compare SCAN_ID_1 SCAN_ID_2
```

### Export Scan

```bash
python argus_db.py export SCAN_ID --output FILE [OPTIONS]

Options:
  --format FORMAT     Output format (json) (default: json)
```

### Delete Scan

```bash
python argus_db.py delete SCAN_ID [OPTIONS]

Options:
  --yes               Skip confirmation prompt
```

### Schedule Management

```bash
# Add job
python argus_db.py schedule add \
  --name NAME \
  --url URL \
  --schedule TYPE \
  [--time TIME] \
  [--modules MODULES] \
  [--email EMAIL]

# List jobs
python argus_db.py schedule list

# Show job
python argus_db.py schedule show JOB_ID

# Pause job
python argus_db.py schedule pause JOB_ID

# Resume job
python argus_db.py schedule resume JOB_ID

# Delete job
python argus_db.py schedule delete JOB_ID [--yes]
```

## Database Schema

### Tables

**scans**: Scan metadata
- `id`: Primary key
- `target_url`: Scanned URL
- `start_time`, `end_time`: Scan timestamps
- `duration_seconds`: Scan duration
- `status`: completed, failed, cancelled
- `total_requests`, `total_findings`: Statistics
- `critical_count`, `high_count`, `medium_count`, `low_count`, `info_count`: Severity counts
- `config_json`: Scan configuration (JSON)
- `modules_used`: Comma-separated module list
- `scanner_version`: Scanner version

**findings**: Individual vulnerabilities
- `id`: Primary key
- `scan_id`: Foreign key to scans
- `type`: Vulnerability type (sqli, xss, etc.)
- `severity`: critical, high, medium, low, info
- `title`, `description`: Vulnerability details
- `url`, `method`, `parameter`: Location
- `payload`, `evidence`: Attack details
- `request_data`, `response_data`: Full HTTP data (JSON)
- `owasp_category`, `cwe_ids`, `pci_dss_refs`, `hipaa_refs`: Compliance mappings
- `remediation`, `reference_urls`: Remediation info
- `confidence`: Detection confidence (0.0-1.0)
- `false_positive`, `verified`: Flags

**targets**: Tracked targets
- `id`: Primary key
- `url`: Target URL (unique)
- `first_seen`, `last_scanned`: Timestamps
- `scan_count`: Number of scans
- `total_findings`, `critical_findings`, `high_findings`: Statistics

**jobs**: Scheduled jobs
- `id`: Primary key
- `name`: Job name
- `target_url`: Target to scan
- `schedule_type`, `schedule_value`: Schedule configuration
- `config_json`, `modules`: Scan configuration
- `is_active`: Job enabled/disabled
- `last_run`, `next_run`: Run timestamps
- `run_count`: Execution count
- `notify_on_complete`, `notify_on_new_findings`: Notification settings
- `notification_email`: Email for notifications

**users**: User accounts (multi-user setups)
- `id`: Primary key
- `username`, `email`: User credentials
- `password_hash`: Hashed password
- `role`: admin, user, readonly
- `is_active`: Account status

## Best Practices

### Performance

1. **Use Indexes**: The schema includes indexes on frequently queried columns
2. **Batch Operations**: Store multiple scans in a transaction when possible
3. **Limit Results**: Use `limit` parameter to avoid loading large datasets
4. **PostgreSQL for Scale**: Use PostgreSQL for high-volume production environments

### Data Management

1. **Regular Backups**: Back up your database regularly
   ```bash
   # SQLite
   cp argus.db argus.db.backup
   
   # PostgreSQL
   pg_dump argus > argus_backup.sql
   ```

2. **Archive Old Scans**: Export and delete old scans to keep database size manageable
   ```bash
   python argus_db.py export 42 --output scan_42.json
   python argus_db.py delete 42 --yes
   ```

3. **Monitor Growth**: Track database size and finding counts

### Security

1. **Protect Database Files**: Restrict access to database files
   ```bash
   chmod 600 argus.db
   ```

2. **Use Strong Credentials**: For PostgreSQL, use strong passwords
3. **Encrypt Sensitive Data**: Consider encrypting database files at rest
4. **Audit Access**: Log database operations in production

## Integration

### With Argus Scanner

The database layer integrates seamlessly with the main Argus scanner:

```python
from argus.scanner import ArgusScanner
from argus.database import ScanDatabase

# Create scanner with database
db = ScanDatabase('sqlite:///argus.db')
scanner = ArgusScanner(database=db)

# Run scan (automatically stores results)
results = scanner.scan('https://example.com')

print(f"Scan #{results['scan_id']} completed")
print(f"Found {results['findings_count']} vulnerabilities")
```

### With Compliance Mapper

Findings are automatically enriched with compliance data:

```python
from argus.compliance import ComplianceMapper
from argus.database import ScanDatabase

db = ScanDatabase('sqlite:///argus.db')
mapper = ComplianceMapper()

# Retrieve scan and enrich findings
scan = db.get_scan(scan_id)
enriched_findings = mapper.enrich_findings(scan['findings'])

# Findings now include OWASP, CWE, PCI-DSS, HIPAA references
```

## Troubleshooting

### SQLite Locked Database

If you see "database is locked" errors:

```python
# Use timeout
db = ScanDatabase('sqlite:///argus.db?timeout=30')

# Or switch to PostgreSQL for concurrent access
```

### Missing APScheduler

If scheduler fails with "APScheduler required":

```bash
pip install apscheduler
```

### PostgreSQL Connection Issues

```python
# Test connection
import psycopg2
conn = psycopg2.connect('postgresql://user:pass@localhost/argus')
conn.close()

# Check PostgreSQL is running
# sudo systemctl status postgresql
```

### Large Database Size

Optimize database size:

```bash
# SQLite
sqlite3 argus.db 'VACUUM;'

# PostgreSQL
psql argus -c 'VACUUM FULL;'
```

## Examples

### Example 1: Weekly Report

Generate a weekly vulnerability report:

```python
from datetime import datetime, timedelta
from argus.database import ScanDatabase

db = ScanDatabase('sqlite:///argus.db')

# Get trend for last 7 days
trend = db.get_vulnerability_trend(days=7)

print("Weekly Security Report")
print("=" * 50)
print(f"Period: {datetime.now() - timedelta(days=7)} to {datetime.now()}")
print(f"Total Scans: {trend['summary']['total_scans']}")
print(f"Total Findings: {trend['summary']['total_findings']}")

# Group by severity
critical = sum(day['critical'] or 0 for day in trend['daily_counts'])
high = sum(day['high'] or 0 for day in trend['daily_counts'])
print(f"Critical: {critical}, High: {high}")

db.close()
```

### Example 2: Regression Detection

Detect security regressions:

```python
# Get last two scans
scans = db.list_scans(limit=2)
if len(scans) >= 2:
    comparison = db.compare_scans(scans[1]['id'], scans[0]['id'])
    
    if comparison['summary']['new_count'] > 0:
        print(f"⚠️  REGRESSION: {comparison['summary']['new_count']} new vulnerabilities!")
        for finding in comparison['comparison']['new']:
            if finding['severity'] in ['critical', 'high']:
                print(f"  [{finding['severity']}] {finding['title']}")
```

### Example 3: Compliance Dashboard

Generate compliance summary:

```python
scan = db.get_scan(scan_id)
compliance_stats = {
    'owasp': set(),
    'cwe': set(),
    'pci_dss': set(),
    'hipaa': set()
}

for finding in scan['findings']:
    if finding.get('owasp_category'):
        compliance_stats['owasp'].add(finding['owasp_category'])
    if finding.get('cwe_ids'):
        for cwe in finding['cwe_ids'].split(','):
            compliance_stats['cwe'].add(cwe)

print("Compliance Summary:")
print(f"OWASP Categories: {len(compliance_stats['owasp'])}")
print(f"CWE IDs: {len(compliance_stats['cwe'])}")
```

## API Reference

### ScanDatabase

**Constructor:**
```python
ScanDatabase(connection_string: str)
```

**Methods:**

- `store_scan(target_url, findings, stats, config=None, status='completed', notes=None) -> int`
- `get_scan(scan_id: int) -> Optional[Dict]`
- `list_scans(target_url=None, limit=100, offset=0, status=None) -> List[Dict]`
- `get_vulnerability_trend(target_url=None, days=30) -> Dict`
- `compare_scans(scan_id_1: int, scan_id_2: int) -> Dict`
- `delete_scan(scan_id: int) -> bool`
- `close()`

### ScanScheduler

**Constructor:**
```python
ScanScheduler(database: ScanDatabase, scan_function: Optional[Callable])
```

**Methods:**

- `add_job(name, target_url, schedule_type, schedule_value=None, config=None, modules=None, notify_on_complete=False, notify_on_new_findings=True, notification_email=None) -> int`
- `list_jobs(active_only=False) -> List[Dict]`
- `get_job(job_id: int) -> Optional[Dict]`
- `pause_job(job_id: int)`
- `resume_job(job_id: int)`
- `delete_job(job_id: int)`
- `start()`
- `stop()`

## Support

For issues or questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review the [Examples](#examples)
- Consult the [API Reference](#api-reference)

---

**Version**: 1.0  
**Last Updated**: October 2025
