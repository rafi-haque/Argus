#!/usr/bin/env python3
"""
Demo script for Argus Database Layer

Demonstrates:
1. Storing scan results
2. Retrieving scans
3. Trend analysis
4. Scan comparison
5. Scheduled jobs
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from argus.database.storage import ScanDatabase
from argus.database.scheduler import ScanScheduler


def generate_sample_findings(count: int = 5) -> list:
    """Generate sample vulnerability findings."""
    vulnerability_types = [
        ('SQL Injection', 'critical', 'sqli', 'Potential SQL injection vulnerability'),
        ('XSS', 'high', 'xss', 'Cross-site scripting vulnerability detected'),
        ('CSRF', 'medium', 'csrf', 'Missing CSRF token'),
        ('Security Headers', 'low', 'headers', 'Missing security headers'),
        ('Information Disclosure', 'info', 'info_disclosure', 'Server version disclosed'),
    ]
    
    findings = []
    for i in range(count):
        vuln = random.choice(vulnerability_types)
        finding = {
            'type': vuln[2],
            'severity': vuln[1],
            'title': vuln[0],
            'description': vuln[3],
            'url': f'https://example.com/page{i}',
            'method': 'GET',
            'parameter': f'param{i}',
            'payload': f"' OR 1=1--",
            'evidence': 'SQL error in response',
            'remediation': 'Use parameterized queries',
            'confidence': 0.8 + random.random() * 0.2,
            'compliance': {
                'owasp': {'id': 'A03:2021', 'category': 'Injection'},
                'cwe': {'ids': [89]},
                'pci_dss': {'requirements': ['6.2.4']},
                'hipaa': {'controls': ['§164.308(a)(1)(ii)(D)']}
            }
        }
        findings.append(finding)
    
    return findings


def demo_basic_storage():
    """Demo 1: Basic storage and retrieval."""
    print("\n" + "="*70)
    print("DEMO 1: Basic Storage and Retrieval")
    print("="*70)
    
    # Create database
    db = ScanDatabase('sqlite:///demo_argus.db')
    
    # Store a scan
    print("\n✓ Storing scan result...")
    findings = generate_sample_findings(8)
    
    stats = {
        'start_time': datetime.now() - timedelta(hours=1),
        'end_time': datetime.now(),
        'total_requests': 150,
        'version': '1.0'
    }
    
    config = {
        'modules': ['xss', 'sqli', 'headers'],
        'depth': 3,
        'timeout': 10
    }
    
    scan_id = db.store_scan(
        target_url='https://example.com',
        findings=findings,
        stats=stats,
        config=config,
        status='completed',
        notes='Demo scan'
    )
    
    print(f"  → Scan #{scan_id} stored with {len(findings)} findings")
    
    # Retrieve the scan
    print("\n✓ Retrieving scan...")
    scan = db.get_scan(scan_id)
    
    print(f"  → Scan #{scan['id']}")
    print(f"  → Target: {scan['target_url']}")
    print(f"  → Duration: {scan['duration_seconds']:.2f}s")
    print(f"  → Findings: {scan['total_findings']}")
    print(f"  → Critical: {scan['critical_count']}, High: {scan['high_count']}, "
          f"Medium: {scan['medium_count']}, Low: {scan['low_count']}")
    
    # List scans
    print("\n✓ Listing all scans...")
    scans = db.list_scans(limit=5)
    print(f"  → Found {len(scans)} scan(s)")
    
    for s in scans:
        print(f"     #{s['id']}: {s['target_url']} - {s['total_findings']} findings")
    
    db.close()
    print("\n✅ Demo 1 completed")


def demo_multiple_scans():
    """Demo 2: Store multiple scans for trend analysis."""
    print("\n" + "="*70)
    print("DEMO 2: Multiple Scans Over Time")
    print("="*70)
    
    db = ScanDatabase('sqlite:///demo_argus.db')
    
    print("\n✓ Storing 7 days of scan data...")
    
    target_url = 'https://example.com'
    scan_ids = []
    
    for day in range(7, 0, -1):
        # Generate findings with decreasing severity (showing improvement)
        finding_count = 10 - day  # More findings in earlier scans
        findings = generate_sample_findings(finding_count)
        
        scan_date = datetime.now() - timedelta(days=day)
        stats = {
            'start_time': scan_date,
            'end_time': scan_date + timedelta(minutes=30),
            'total_requests': 100,
            'version': '1.0'
        }
        
        scan_id = db.store_scan(
            target_url=target_url,
            findings=findings,
            stats=stats,
            status='completed'
        )
        
        scan_ids.append(scan_id)
        print(f"  → Day {8-day}: Scan #{scan_id} with {finding_count} findings")
    
    db.close()
    print(f"\n✅ Demo 2 completed: {len(scan_ids)} scans stored")


def demo_trend_analysis():
    """Demo 3: Vulnerability trend analysis."""
    print("\n" + "="*70)
    print("DEMO 3: Vulnerability Trend Analysis")
    print("="*70)
    
    db = ScanDatabase('sqlite:///demo_argus.db')
    
    print("\n✓ Analyzing 7-day trend...")
    trend = db.get_vulnerability_trend(days=7)
    
    print(f"\n  Summary:")
    print(f"  → Total Scans: {trend['summary']['total_scans']}")
    print(f"  → Total Findings: {trend['summary']['total_findings']}")
    print(f"  → Avg Per Scan: {trend['summary']['avg_findings_per_scan']:.1f}")
    
    print(f"\n  Daily Breakdown:")
    print(f"  {'Date':<12} {'Scans':<8} {'Findings':<10} {'Critical':<10} {'High':<8}")
    print(f"  {'-'*50}")
    
    for day in trend['daily_counts']:
        print(f"  {str(day['scan_date']):<12} {day['scan_count']:<8} "
              f"{day['total_findings'] or 0:<10} {day['critical'] or 0:<10} "
              f"{day['high'] or 0:<8}")
    
    db.close()
    print("\n✅ Demo 3 completed")


def demo_scan_comparison():
    """Demo 4: Compare two scans."""
    print("\n" + "="*70)
    print("DEMO 4: Scan Comparison")
    print("="*70)
    
    db = ScanDatabase('sqlite:///demo_argus.db')
    
    # Get first and last scans
    scans = db.list_scans(limit=100)
    if len(scans) < 2:
        print("\n⚠ Need at least 2 scans for comparison")
        db.close()
        return
    
    scan_1_id = scans[-1]['id']  # Oldest
    scan_2_id = scans[0]['id']   # Newest
    
    print(f"\n✓ Comparing scan #{scan_1_id} vs #{scan_2_id}...")
    
    comparison = db.compare_scans(scan_1_id, scan_2_id)
    
    print(f"\n  Scan 1:")
    print(f"  → ID: #{comparison['scan_1']['id']}")
    print(f"  → Date: {comparison['scan_1']['start_time']}")
    print(f"  → Findings: {comparison['scan_1']['total_findings']}")
    
    print(f"\n  Scan 2:")
    print(f"  → ID: #{comparison['scan_2']['id']}")
    print(f"  → Date: {comparison['scan_2']['start_time']}")
    print(f"  → Findings: {comparison['scan_2']['total_findings']}")
    
    summary = comparison['summary']
    print(f"\n  Comparison:")
    print(f"  → New:       {summary['new_count']}")
    print(f"  → Fixed:     {summary['fixed_count']}")
    print(f"  → Changed:   {summary['changed_count']}")
    print(f"  → Unchanged: {summary['unchanged_count']}")
    
    if comparison['comparison']['new']:
        print(f"\n  New Vulnerabilities:")
        for finding in comparison['comparison']['new'][:3]:
            print(f"  → [{finding['severity'].upper()}] {finding['title']}")
    
    if comparison['comparison']['fixed']:
        print(f"\n  Fixed Vulnerabilities:")
        for finding in comparison['comparison']['fixed'][:3]:
            print(f"  → [{finding['severity'].upper()}] {finding['title']}")
    
    db.close()
    print("\n✅ Demo 4 completed")


def demo_scheduler():
    """Demo 5: Scheduled jobs."""
    print("\n" + "="*70)
    print("DEMO 5: Scheduled Jobs")
    print("="*70)
    
    db = ScanDatabase('sqlite:///demo_argus.db')
    scheduler = ScanScheduler(db)
    
    print("\n✓ Adding scheduled jobs...")
    
    # Daily scan
    job_1 = scheduler.add_job(
        name='Daily Security Scan',
        target_url='https://example.com',
        schedule_type='daily',
        schedule_value='02:00',
        modules=['xss', 'sqli'],
        notify_on_new_findings=True
    )
    print(f"  → Job #{job_1}: Daily scan at 2:00 AM")
    
    # Weekly scan
    job_2 = scheduler.add_job(
        name='Weekly Full Scan',
        target_url='https://example.com/admin',
        schedule_type='weekly',
        schedule_value='MON 14:00',
        modules=['xss', 'sqli', 'csrf', 'headers'],
        notify_on_complete=True
    )
    print(f"  → Job #{job_2}: Weekly scan on Mondays at 2:00 PM")
    
    # List jobs
    print("\n✓ Listing scheduled jobs...")
    jobs = scheduler.list_jobs()
    
    for job in jobs:
        status = "Active" if job['is_active'] else "Paused"
        print(f"  → #{job['id']}: {job['name']} - {job['schedule_type']} ({status})")
        print(f"     Target: {job['target_url']}")
        print(f"     Next run: {job['next_run']}")
    
    # Pause a job
    print(f"\n✓ Pausing job #{job_1}...")
    scheduler.pause_job(job_1)
    print(f"  → Job #{job_1} paused")
    
    # Resume the job
    print(f"\n✓ Resuming job #{job_1}...")
    scheduler.resume_job(job_1)
    print(f"  → Job #{job_1} resumed")
    
    db.close()
    print("\n✅ Demo 5 completed")


def main():
    """Run all demos."""
    print("\n" + "="*70)
    print("🛡️  ARGUS DATABASE LAYER - DEMONSTRATION")
    print("="*70)
    print("\nThis demo will:")
    print("  1. Store scan results in SQLite database")
    print("  2. Store multiple scans over 7 days")
    print("  3. Analyze vulnerability trends")
    print("  4. Compare two scans")
    print("  5. Manage scheduled jobs")
    
    try:
        # Run demos
        demo_basic_storage()
        demo_multiple_scans()
        demo_trend_analysis()
        demo_scan_comparison()
        demo_scheduler()
        
        # Summary
        print("\n" + "="*70)
        print("✅ All demos completed successfully!")
        print("="*70)
        print("\nDatabase file: demo_argus.db")
        print("\nTry these commands:")
        print("  python argus_db.py list --db demo_argus.db")
        print("  python argus_db.py show 1 --db demo_argus.db")
        print("  python argus_db.py trend --days 7 --db demo_argus.db")
        print("  python argus_db.py schedule list --db demo_argus.db")
        print()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
