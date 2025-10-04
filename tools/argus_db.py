#!/usr/bin/env python3
"""
Argus Database Management CLI

Manage scan database, view scan history, analyze trends, and schedule jobs.

Usage:
    # List recent scans
    python argus_db.py list --limit 10
    
    # View a specific scan
    python argus_db.py show 42
    
    # Get vulnerability trend
    python argus_db.py trend --days 30
    
    # Compare two scans
    python argus_db.py compare 10 20
    
    # Add scheduled job
    python argus_db.py schedule add --name "Daily Scan" --url https://example.com --schedule daily --time 02:00
    
    # List scheduled jobs
    python argus_db.py schedule list
    
    # Export scan to JSON
    python argus_db.py export 42 --output scan_42.json
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from argus.database.storage import ScanDatabase
from argus.database.scheduler import ScanScheduler


class DatabaseCLI:
    """CLI interface for database operations."""
    
    def __init__(self, db_path: str = 'argus.db'):
        """Initialize database connection."""
        self.db_path = db_path
        self.connection_string = f'sqlite:///{db_path}'
        self.db = ScanDatabase(self.connection_string)
    
    def list_scans(self, limit: int = 20, target: Optional[str] = None, status: Optional[str] = None):
        """List recent scans."""
        scans = self.db.list_scans(target_url=target, limit=limit, status=status)
        
        if not scans:
            print("No scans found")
            return
        
        print(f"\n{'ID':<6} {'Target':<40} {'Date':<20} {'Findings':<10} {'Status':<12}")
        print("=" * 95)
        
        for scan in scans:
            scan_id = scan['id']
            target_url = scan['target_url'][:38] + '...' if len(scan['target_url']) > 40 else scan['target_url']
            start_time = scan['start_time']
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            date_str = start_time.strftime('%Y-%m-%d %H:%M')
            findings = scan['total_findings']
            status_str = scan['status']
            
            # Color code by findings
            if findings > 10:
                findings_str = f"\033[91m{findings}\033[0m"  # Red
            elif findings > 5:
                findings_str = f"\033[93m{findings}\033[0m"  # Yellow
            else:
                findings_str = f"\033[92m{findings}\033[0m"  # Green
            
            print(f"{scan_id:<6} {target_url:<40} {date_str:<20} {findings_str:<10} {status_str:<12}")
        
        print()
    
    def show_scan(self, scan_id: int, show_findings: bool = True):
        """Show details of a specific scan."""
        scan = self.db.get_scan(scan_id)
        
        if not scan:
            print(f"Scan #{scan_id} not found")
            return
        
        # Display scan metadata
        print(f"\n{'='*70}")
        print(f"SCAN #{scan['id']}")
        print(f"{'='*70}")
        print(f"Target URL:      {scan['target_url']}")
        print(f"Start Time:      {scan['start_time']}")
        print(f"End Time:        {scan['end_time']}")
        print(f"Duration:        {scan['duration_seconds']:.2f} seconds")
        print(f"Status:          {scan['status']}")
        print(f"Total Requests:  {scan['total_requests']}")
        print(f"Scanner Version: {scan.get('scanner_version', 'N/A')}")
        
        if scan.get('modules_used'):
            print(f"Modules:         {scan['modules_used']}")
        
        # Display statistics
        print(f"\n{'Findings Summary':-^70}")
        print(f"Total:    {scan['total_findings']}")
        print(f"Critical: {scan['critical_count']}")
        print(f"High:     {scan['high_count']}")
        print(f"Medium:   {scan['medium_count']}")
        print(f"Low:      {scan['low_count']}")
        print(f"Info:     {scan['info_count']}")
        
        if show_findings and scan['findings']:
            print(f"\n{'Findings Details':-^70}")
            
            for i, finding in enumerate(scan['findings'], 1):
                severity = finding['severity'].upper()
                severity_color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[91m',
                    'MEDIUM': '\033[93m',    # Yellow
                    'LOW': '\033[92m',       # Green
                    'INFO': '\033[94m'       # Blue
                }.get(severity, '')
                
                print(f"\n{i}. [{severity_color}{severity}\033[0m] {finding['title']}")
                print(f"   Type: {finding['type']}")
                print(f"   URL:  {finding['url']}")
                
                if finding.get('parameter'):
                    print(f"   Parameter: {finding['parameter']}")
                
                if finding.get('payload'):
                    payload = finding['payload'][:100] + '...' if len(finding['payload']) > 100 else finding['payload']
                    print(f"   Payload: {payload}")
                
                if finding.get('owasp_category'):
                    print(f"   OWASP: {finding['owasp_category']}")
                
                if finding.get('cwe_ids'):
                    print(f"   CWE: {finding['cwe_ids']}")
        
        print()
    
    def show_trend(self, days: int = 30, target: Optional[str] = None):
        """Show vulnerability trend over time."""
        trend = self.db.get_vulnerability_trend(target_url=target, days=days)
        
        if not trend['daily_counts']:
            print(f"No scans found in the last {days} days")
            return
        
        print(f"\n{'='*80}")
        print(f"VULNERABILITY TREND - Last {days} Days")
        if target:
            print(f"Target: {target}")
        print(f"{'='*80}")
        
        # Summary
        summary = trend['summary']
        print("\nSummary:")
        print(f"  Total Scans:    {summary['total_scans']}")
        print(f"  Total Findings: {summary['total_findings']}")
        print(f"  Avg Per Scan:   {summary['avg_findings_per_scan']:.1f}")
        
        # Daily breakdown
        print(f"\n{'Date':<12} {'Scans':<8} {'Total':<8} {'Critical':<10} {'High':<8} {'Medium':<8} {'Low':<8}")
        print("-" * 80)
        
        for day in trend['daily_counts']:
            date_str = str(day['scan_date'])
            print(f"{date_str:<12} {day['scan_count']:<8} {day['total_findings'] or 0:<8} "
                  f"{day['critical'] or 0:<10} {day['high'] or 0:<8} "
                  f"{day['medium'] or 0:<8} {day['low'] or 0:<8}")
        
        print()
    
    def compare_scans(self, scan_id_1: int, scan_id_2: int):
        """Compare two scans."""
        try:
            comparison = self.db.compare_scans(scan_id_1, scan_id_2)
        except ValueError as e:
            print(f"Error: {e}")
            return
        
        print(f"\n{'='*80}")
        print("SCAN COMPARISON")
        print(f"{'='*80}")
        
        # Scan info
        scan1 = comparison['scan_1']
        scan2 = comparison['scan_2']
        
        print(f"\nScan 1: #{scan1['id']} - {scan1['target_url']}")
        print(f"  Date: {scan1['start_time']}")
        print(f"  Findings: {scan1['total_findings']}")
        
        print(f"\nScan 2: #{scan2['id']} - {scan2['target_url']}")
        print(f"  Date: {scan2['start_time']}")
        print(f"  Findings: {scan2['total_findings']}")
        
        # Summary
        summary = comparison['summary']
        print(f"\n{'Summary':-^80}")
        print(f"  New Vulnerabilities:     {summary['new_count']}")
        print(f"  Fixed Vulnerabilities:   {summary['fixed_count']}")
        print(f"  Changed Severity:        {summary['changed_count']}")
        print(f"  Unchanged:               {summary['unchanged_count']}")
        
        # New findings
        if comparison['comparison']['new']:
            print(f"\n{'NEW Vulnerabilities':-^80}")
            for i, finding in enumerate(comparison['comparison']['new'], 1):
                print(f"{i}. [{finding['severity'].upper()}] {finding['title']}")
                print(f"   {finding['url']}")
        
        # Fixed findings
        if comparison['comparison']['fixed']:
            print(f"\n{'FIXED Vulnerabilities':-^80}")
            for i, finding in enumerate(comparison['comparison']['fixed'], 1):
                print(f"{i}. [{finding['severity'].upper()}] {finding['title']}")
                print(f"   {finding['url']}")
        
        # Changed findings
        if comparison['comparison']['changed']:
            print(f"\n{'CHANGED Severity':-^80}")
            for i, item in enumerate(comparison['comparison']['changed'], 1):
                finding = item['finding']
                print(f"{i}. {finding['title']}")
                print(f"   {finding['url']}")
                print(f"   {item['old_severity']} → {item['new_severity']}")
        
        print()
    
    def export_scan(self, scan_id: int, output_file: str, format: str = 'json'):
        """Export scan to file."""
        scan = self.db.get_scan(scan_id)
        
        if not scan:
            print(f"Scan #{scan_id} not found")
            return
        
        # Convert datetime objects to strings for JSON serialization
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        # Recursively convert datetimes
        def process_dict(d):
            if isinstance(d, dict):
                return {k: process_dict(v) for k, v in d.items()}
            elif isinstance(d, list):
                return [process_dict(item) for item in d]
            else:
                return convert_datetime(d)
        
        scan_processed = process_dict(scan)
        
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(scan_processed, f, indent=2)
        else:
            print(f"Unsupported format: {format}")
            return
        
        print(f"Exported scan #{scan_id} to {output_file}")
    
    def delete_scan(self, scan_id: int, confirm: bool = False):
        """Delete a scan."""
        if not confirm:
            response = input(f"Are you sure you want to delete scan #{scan_id}? (y/N): ")
            if response.lower() != 'y':
                print("Cancelled")
                return
        
        if self.db.delete_scan(scan_id):
            print(f"Deleted scan #{scan_id}")
        else:
            print(f"Scan #{scan_id} not found")
    
    def schedule_add(
        self,
        name: str,
        url: str,
        schedule_type: str,
        time: Optional[str] = None,
        modules: Optional[str] = None,
        email: Optional[str] = None
    ):
        """Add a scheduled job."""
        scheduler = ScanScheduler(self.db)
        
        modules_list = modules.split(',') if modules else None
        
        job_id = scheduler.add_job(
            name=name,
            target_url=url,
            schedule_type=schedule_type,
            schedule_value=time,
            modules=modules_list,
            notification_email=email
        )
        
        print(f"Added job #{job_id}: {name}")
    
    def schedule_list(self):
        """List scheduled jobs."""
        scheduler = ScanScheduler(self.db)
        jobs = scheduler.list_jobs()
        
        if not jobs:
            print("No scheduled jobs")
            return
        
        print(f"\n{'ID':<6} {'Name':<30} {'Target':<30} {'Schedule':<15} {'Active':<8}")
        print("=" * 95)
        
        for job in jobs:
            job_id = job['id']
            name = job['name'][:28] + '...' if len(job['name']) > 30 else job['name']
            target = job['target_url'][:28] + '...' if len(job['target_url']) > 30 else job['target_url']
            schedule = f"{job['schedule_type']}"
            if job['schedule_value']:
                schedule += f" {job['schedule_value']}"
            active = "Yes" if job['is_active'] else "No"
            
            print(f"{job_id:<6} {name:<30} {target:<30} {schedule:<15} {active:<8}")
        
        print()
    
    def schedule_show(self, job_id: int):
        """Show job details."""
        scheduler = ScanScheduler(self.db)
        job = scheduler.get_job(job_id)
        
        if not job:
            print(f"Job #{job_id} not found")
            return
        
        print(f"\n{'='*70}")
        print(f"JOB #{job['id']}")
        print(f"{'='*70}")
        print(f"Name:         {job['name']}")
        print(f"Target URL:   {job['target_url']}")
        print(f"Schedule:     {job['schedule_type']} {job.get('schedule_value', '')}")
        print(f"Active:       {'Yes' if job['is_active'] else 'No'}")
        print(f"Run Count:    {job['run_count']}")
        
        if job.get('last_run'):
            print(f"Last Run:     {job['last_run']}")
        if job.get('next_run'):
            print(f"Next Run:     {job['next_run']}")
        
        if job.get('modules'):
            print(f"Modules:      {job['modules']}")
        
        if job.get('notification_email'):
            print(f"Email:        {job['notification_email']}")
        
        print()
    
    def schedule_delete(self, job_id: int, confirm: bool = False):
        """Delete a scheduled job."""
        if not confirm:
            response = input(f"Are you sure you want to delete job #{job_id}? (y/N): ")
            if response.lower() != 'y':
                print("Cancelled")
                return
        
        scheduler = ScanScheduler(self.db)
        scheduler.delete_job(job_id)
        print(f"Deleted job #{job_id}")
    
    def schedule_pause(self, job_id: int):
        """Pause a scheduled job."""
        scheduler = ScanScheduler(self.db)
        scheduler.pause_job(job_id)
        print(f"Paused job #{job_id}")
    
    def schedule_resume(self, job_id: int):
        """Resume a scheduled job."""
        scheduler = ScanScheduler(self.db)
        scheduler.resume_job(job_id)
        print(f"Resumed job #{job_id}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Argus Database Management CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--db', default='argus.db', help='Database file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List scans')
    list_parser.add_argument('--limit', type=int, default=20, help='Maximum number of scans to show')
    list_parser.add_argument('--target', help='Filter by target URL')
    list_parser.add_argument('--status', help='Filter by status')
    
    # Show command
    show_parser = subparsers.add_parser('show', help='Show scan details')
    show_parser.add_argument('scan_id', type=int, help='Scan ID')
    show_parser.add_argument('--no-findings', action='store_true', help='Don\'t show findings')
    
    # Trend command
    trend_parser = subparsers.add_parser('trend', help='Show vulnerability trend')
    trend_parser.add_argument('--days', type=int, default=30, help='Number of days to analyze')
    trend_parser.add_argument('--target', help='Filter by target URL')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two scans')
    compare_parser.add_argument('scan_id_1', type=int, help='First scan ID (older)')
    compare_parser.add_argument('scan_id_2', type=int, help='Second scan ID (newer)')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export scan to file')
    export_parser.add_argument('scan_id', type=int, help='Scan ID')
    export_parser.add_argument('--output', required=True, help='Output file path')
    export_parser.add_argument('--format', default='json', choices=['json'], help='Output format')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete', help='Delete a scan')
    delete_parser.add_argument('scan_id', type=int, help='Scan ID')
    delete_parser.add_argument('--yes', action='store_true', help='Skip confirmation')
    
    # Schedule subcommand
    schedule_parser = subparsers.add_parser('schedule', help='Manage scheduled jobs')
    schedule_subparsers = schedule_parser.add_subparsers(dest='schedule_command', help='Schedule commands')
    
    # Schedule add
    schedule_add_parser = schedule_subparsers.add_parser('add', help='Add scheduled job')
    schedule_add_parser.add_argument('--name', required=True, help='Job name')
    schedule_add_parser.add_argument('--url', required=True, help='Target URL')
    schedule_add_parser.add_argument('--schedule', required=True, 
                                     choices=['once', 'daily', 'weekly', 'monthly', 'cron'],
                                     help='Schedule type')
    schedule_add_parser.add_argument('--time', help='Schedule time (e.g., 14:00, MON 14:00, 15 14:00)')
    schedule_add_parser.add_argument('--modules', help='Comma-separated list of modules')
    schedule_add_parser.add_argument('--email', help='Notification email')
    
    # Schedule list
    schedule_subparsers.add_parser('list', help='List scheduled jobs')
    
    # Schedule show
    schedule_show_parser = schedule_subparsers.add_parser('show', help='Show job details')
    schedule_show_parser.add_argument('job_id', type=int, help='Job ID')
    
    # Schedule delete
    schedule_delete_parser = schedule_subparsers.add_parser('delete', help='Delete scheduled job')
    schedule_delete_parser.add_argument('job_id', type=int, help='Job ID')
    schedule_delete_parser.add_argument('--yes', action='store_true', help='Skip confirmation')
    
    # Schedule pause
    schedule_pause_parser = schedule_subparsers.add_parser('pause', help='Pause scheduled job')
    schedule_pause_parser.add_argument('job_id', type=int, help='Job ID')
    
    # Schedule resume
    schedule_resume_parser = schedule_subparsers.add_parser('resume', help='Resume scheduled job')
    schedule_resume_parser.add_argument('job_id', type=int, help='Job ID')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = DatabaseCLI(args.db)
    
    try:
        # Execute command
        if args.command == 'list':
            cli.list_scans(limit=args.limit, target=args.target, status=args.status)
        
        elif args.command == 'show':
            cli.show_scan(args.scan_id, show_findings=not args.no_findings)
        
        elif args.command == 'trend':
            cli.show_trend(days=args.days, target=args.target)
        
        elif args.command == 'compare':
            cli.compare_scans(args.scan_id_1, args.scan_id_2)
        
        elif args.command == 'export':
            cli.export_scan(args.scan_id, args.output, args.format)
        
        elif args.command == 'delete':
            cli.delete_scan(args.scan_id, confirm=args.yes)
        
        elif args.command == 'schedule':
            if args.schedule_command == 'add':
                cli.schedule_add(
                    name=args.name,
                    url=args.url,
                    schedule_type=args.schedule,
                    time=args.time,
                    modules=args.modules,
                    email=args.email
                )
            
            elif args.schedule_command == 'list':
                cli.schedule_list()
            
            elif args.schedule_command == 'show':
                cli.schedule_show(args.job_id)
            
            elif args.schedule_command == 'delete':
                cli.schedule_delete(args.job_id, confirm=args.yes)
            
            elif args.schedule_command == 'pause':
                cli.schedule_pause(args.job_id)
            
            elif args.schedule_command == 'resume':
                cli.schedule_resume(args.job_id)
            
            else:
                schedule_parser.print_help()
        
        else:
            parser.print_help()
    
    finally:
        cli.db.close()


if __name__ == '__main__':
    main()
