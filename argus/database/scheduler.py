"""
Scan scheduler for Argus scanner.

Provides automated scheduling of scans with:
- Cron-like scheduling (daily, weekly, monthly, custom)
- Background job execution
- Notification on completion/new findings
- Job management (add, remove, pause, resume)

Usage:
    db = ScanDatabase('sqlite:///argus.db')
    scheduler = ScanScheduler(db)
    
    # Add a daily scan
    job_id = scheduler.add_job(
        name='Daily Security Scan',
        target_url='https://example.com',
        schedule_type='daily',
        schedule_value='02:00',  # 2 AM
        config={'modules': ['xss', 'sqli']}
    )
    
    # Start the scheduler
    scheduler.start()
    
    # List all jobs
    jobs = scheduler.list_jobs()
    
    # Stop the scheduler
    scheduler.stop()
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
import json
from concurrent.futures import ThreadPoolExecutor

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.date import DateTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

from argus.database.storage import ScanDatabase

logger = logging.getLogger(__name__)


@dataclass
class JobRecord:
    """Represents a scheduled job."""
    id: Optional[int]
    name: str
    target_url: str
    schedule_type: str
    schedule_value: Optional[str]
    config_json: Optional[str]
    modules: Optional[str]
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    run_count: int
    notify_on_complete: bool
    notify_on_new_findings: bool
    notification_email: Optional[str]
    created_by: Optional[int]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class ScanScheduler:
    """Manages scheduled scans."""
    
    def __init__(
        self,
        database: ScanDatabase,
        scan_function: Optional[Callable] = None
    ):
        """
        Initialize the scheduler.
        
        Args:
            database: ScanDatabase instance for storing results
            scan_function: Optional custom scan function to execute
                          If not provided, jobs will be queued but not executed
        """
        if not APSCHEDULER_AVAILABLE:
            raise ImportError(
                "Scheduler requires APScheduler. Install with: pip install apscheduler"
            )
        
        self.database = database
        self.scan_function = scan_function
        self.scheduler = BackgroundScheduler()
        self.executor = ThreadPoolExecutor(max_workers=3)
        self._running = False
    
    def add_job(
        self,
        name: str,
        target_url: str,
        schedule_type: str,
        schedule_value: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        modules: Optional[List[str]] = None,
        notify_on_complete: bool = False,
        notify_on_new_findings: bool = True,
        notification_email: Optional[str] = None
    ) -> int:
        """
        Add a new scheduled job.
        
        Args:
            name: Descriptive name for the job
            target_url: URL to scan
            schedule_type: 'once', 'daily', 'weekly', 'monthly', 'cron'
            schedule_value: Schedule details (time for daily, cron expression, etc.)
            config: Scan configuration
            modules: List of modules to run
            notify_on_complete: Send notification when scan completes
            notify_on_new_findings: Send notification when new findings are detected
            notification_email: Email address for notifications
        
        Returns:
            job_id: ID of the created job
        """
        cursor = self.database.connection.cursor()
        
        try:
            # Calculate next run time
            next_run = self._calculate_next_run(schedule_type, schedule_value)
            
            # Serialize config
            config_json = json.dumps(config) if config else None
            modules_str = ','.join(modules) if modules else None
            
            # Insert job
            insert_query = """
                INSERT INTO jobs (
                    name, target_url, schedule_type, schedule_value,
                    config_json, modules, is_active, next_run,
                    notify_on_complete, notify_on_new_findings, notification_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """ if self.database.db_type == 'sqlite' else """
                INSERT INTO jobs (
                    name, target_url, schedule_type, schedule_value,
                    config_json, modules, is_active, next_run,
                    notify_on_complete, notify_on_new_findings, notification_email
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """
            
            cursor.execute(insert_query, (
                name, target_url, schedule_type, schedule_value,
                config_json, modules_str, True, next_run,
                notify_on_complete, notify_on_new_findings, notification_email
            ))
            
            # Get job ID
            if self.database.db_type == 'sqlite':
                job_id = cursor.lastrowid
            else:
                job_id = cursor.fetchone()[0]
            
            self.database.connection.commit()
            
            # Add to scheduler if running
            if self._running:
                self._schedule_job(job_id)
            
            logger.info(f"Added job #{job_id}: {name}")
            return job_id
            
        except Exception as e:
            self.database.connection.rollback()
            logger.error(f"Failed to add job: {e}")
            raise
    
    def _calculate_next_run(self, schedule_type: str, schedule_value: Optional[str]) -> datetime:
        """Calculate the next run time based on schedule."""
        now = datetime.now()
        
        if schedule_type == 'once':
            # Parse schedule_value as datetime or use now
            if schedule_value:
                return datetime.fromisoformat(schedule_value)
            return now
        
        elif schedule_type == 'daily':
            # schedule_value should be HH:MM
            if schedule_value:
                hour, minute = map(int, schedule_value.split(':'))
                next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                return next_run
            return now + timedelta(days=1)
        
        elif schedule_type == 'weekly':
            # schedule_value should be "MON 14:00", "TUE 09:30", etc.
            if schedule_value:
                day_str, time_str = schedule_value.split()
                days = {'MON': 0, 'TUE': 1, 'WED': 2, 'THU': 3, 'FRI': 4, 'SAT': 5, 'SUN': 6}
                target_day = days.get(day_str.upper(), 0)
                hour, minute = map(int, time_str.split(':'))
                
                # Calculate days until target day
                current_day = now.weekday()
                days_ahead = target_day - current_day
                if days_ahead <= 0:
                    days_ahead += 7
                
                next_run = now + timedelta(days=days_ahead)
                next_run = next_run.replace(hour=hour, minute=minute, second=0, microsecond=0)
                return next_run
            return now + timedelta(weeks=1)
        
        elif schedule_type == 'monthly':
            # schedule_value should be "15 14:00" (day of month and time)
            if schedule_value:
                day_str, time_str = schedule_value.split()
                day = int(day_str)
                hour, minute = map(int, time_str.split(':'))
                
                next_run = now.replace(day=day, hour=hour, minute=minute, second=0, microsecond=0)
                if next_run <= now:
                    # Move to next month
                    if now.month == 12:
                        next_run = next_run.replace(year=now.year + 1, month=1)
                    else:
                        next_run = next_run.replace(month=now.month + 1)
                return next_run
            return now + timedelta(days=30)
        
        else:
            # Default to 1 day from now
            return now + timedelta(days=1)
    
    def _create_trigger(self, schedule_type: str, schedule_value: Optional[str]):
        """Create APScheduler trigger from schedule configuration."""
        if schedule_type == 'once':
            run_date = datetime.fromisoformat(schedule_value) if schedule_value else datetime.now()
            return DateTrigger(run_date=run_date)
        
        elif schedule_type == 'daily':
            if schedule_value:
                hour, minute = map(int, schedule_value.split(':'))
                return CronTrigger(hour=hour, minute=minute)
            return IntervalTrigger(days=1)
        
        elif schedule_type == 'weekly':
            if schedule_value:
                day_str, time_str = schedule_value.split()
                hour, minute = map(int, time_str.split(':'))
                day_map = {'MON': 'mon', 'TUE': 'tue', 'WED': 'wed', 'THU': 'thu',
                          'FRI': 'fri', 'SAT': 'sat', 'SUN': 'sun'}
                day_of_week = day_map.get(day_str.upper(), 'mon')
                return CronTrigger(day_of_week=day_of_week, hour=hour, minute=minute)
            return IntervalTrigger(weeks=1)
        
        elif schedule_type == 'monthly':
            if schedule_value:
                day_str, time_str = schedule_value.split()
                day = int(day_str)
                hour, minute = map(int, time_str.split(':'))
                return CronTrigger(day=day, hour=hour, minute=minute)
            return IntervalTrigger(days=30)
        
        elif schedule_type == 'cron':
            # Parse cron expression
            if schedule_value:
                parts = schedule_value.split()
                if len(parts) == 5:
                    minute, hour, day, month, day_of_week = parts
                    return CronTrigger(
                        minute=minute, hour=hour, day=day,
                        month=month, day_of_week=day_of_week
                    )
            return IntervalTrigger(hours=1)
        
        else:
            # Default to daily
            return IntervalTrigger(days=1)
    
    def _schedule_job(self, job_id: int):
        """Schedule a job with APScheduler."""
        # Get job details
        cursor = self.database.connection.cursor()
        query = "SELECT * FROM jobs WHERE id = ?" if self.database.db_type == 'sqlite' else \
                "SELECT * FROM jobs WHERE id = %s"
        cursor.execute(query, (job_id,))
        row = cursor.fetchone()
        
        if not row:
            return
        
        if self.database.db_type == 'sqlite':
            job = dict(row)
        else:
            columns = [desc[0] for desc in cursor.description]
            job = dict(zip(columns, row))
        
        if not job['is_active']:
            return
        
        # Create trigger
        trigger = self._create_trigger(job['schedule_type'], job['schedule_value'])
        
        # Add to scheduler
        self.scheduler.add_job(
            func=self._execute_job,
            trigger=trigger,
            args=[job_id],
            id=f"job_{job_id}",
            name=job['name'],
            replace_existing=True
        )
        
        logger.info(f"Scheduled job #{job_id}: {job['name']}")
    
    def _execute_job(self, job_id: int):
        """Execute a scheduled job."""
        logger.info(f"Executing job #{job_id}")
        
        # Get job details
        cursor = self.database.connection.cursor()
        query = "SELECT * FROM jobs WHERE id = ?" if self.database.db_type == 'sqlite' else \
                "SELECT * FROM jobs WHERE id = %s"
        cursor.execute(query, (job_id,))
        row = cursor.fetchone()
        
        if not row:
            logger.error(f"Job #{job_id} not found")
            return
        
        if self.database.db_type == 'sqlite':
            job = dict(row)
        else:
            columns = [desc[0] for desc in cursor.description]
            job = dict(zip(columns, row))
        
        try:
            # Update last_run and run_count
            update_query = """
                UPDATE jobs SET last_run = ?, run_count = run_count + 1
                WHERE id = ?
            """ if self.database.db_type == 'sqlite' else """
                UPDATE jobs SET last_run = %s, run_count = run_count + 1
                WHERE id = %s
            """
            cursor.execute(update_query, (datetime.now(), job_id))
            self.database.connection.commit()
            
            # Execute scan if scan_function is provided
            if self.scan_function:
                # Parse config
                config = json.loads(job['config_json']) if job['config_json'] else {}
                
                # Add modules if specified
                if job['modules']:
                    config['modules'] = job['modules'].split(',')
                
                # Execute scan in thread pool to avoid blocking scheduler
                future = self.executor.submit(
                    self.scan_function,
                    job['target_url'],
                    config
                )
                
                # Wait for completion (with timeout)
                result = future.result(timeout=3600)  # 1 hour timeout
                
                logger.info(f"Job #{job_id} completed successfully")
                
                # TODO: Handle notifications
                if job['notify_on_complete'] or job['notify_on_new_findings']:
                    self._send_notification(job, result)
            else:
                logger.warning(f"No scan function configured, job #{job_id} not executed")
        
        except Exception as e:
            logger.error(f"Job #{job_id} failed: {e}")
    
    def _send_notification(self, job: Dict[str, Any], result: Any):
        """Send notification about job completion."""
        # TODO: Implement email notifications
        logger.info(f"Notification for job {job['name']}: {result}")
    
    def start(self):
        """Start the scheduler."""
        if self._running:
            logger.warning("Scheduler already running")
            return
        
        # Load all active jobs
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT id FROM jobs WHERE is_active = 1" if self.database.db_type == 'sqlite' else
                      "SELECT id FROM jobs WHERE is_active = TRUE")
        
        job_ids = [row[0] for row in cursor.fetchall()]
        
        for job_id in job_ids:
            self._schedule_job(job_id)
        
        self.scheduler.start()
        self._running = True
        
        logger.info(f"Scheduler started with {len(job_ids)} jobs")
    
    def stop(self):
        """Stop the scheduler."""
        if not self._running:
            return
        
        self.scheduler.shutdown(wait=True)
        self.executor.shutdown(wait=True)
        self._running = False
        
        logger.info("Scheduler stopped")
    
    def pause_job(self, job_id: int):
        """Pause a job."""
        cursor = self.database.connection.cursor()
        
        update_query = "UPDATE jobs SET is_active = 0 WHERE id = ?" if self.database.db_type == 'sqlite' else \
                      "UPDATE jobs SET is_active = FALSE WHERE id = %s"
        cursor.execute(update_query, (job_id,))
        self.database.connection.commit()
        
        # Remove from scheduler
        if self._running:
            try:
                self.scheduler.remove_job(f"job_{job_id}")
            except:
                pass
        
        logger.info(f"Paused job #{job_id}")
    
    def resume_job(self, job_id: int):
        """Resume a paused job."""
        cursor = self.database.connection.cursor()
        
        update_query = "UPDATE jobs SET is_active = 1 WHERE id = ?" if self.database.db_type == 'sqlite' else \
                      "UPDATE jobs SET is_active = TRUE WHERE id = %s"
        cursor.execute(update_query, (job_id,))
        self.database.connection.commit()
        
        # Add to scheduler
        if self._running:
            self._schedule_job(job_id)
        
        logger.info(f"Resumed job #{job_id}")
    
    def delete_job(self, job_id: int):
        """Delete a job."""
        # Remove from scheduler
        if self._running:
            try:
                self.scheduler.remove_job(f"job_{job_id}")
            except:
                pass
        
        # Delete from database
        cursor = self.database.connection.cursor()
        delete_query = "DELETE FROM jobs WHERE id = ?" if self.database.db_type == 'sqlite' else \
                      "DELETE FROM jobs WHERE id = %s"
        cursor.execute(delete_query, (job_id,))
        self.database.connection.commit()
        
        logger.info(f"Deleted job #{job_id}")
    
    def list_jobs(self, active_only: bool = False) -> List[Dict[str, Any]]:
        """
        List all jobs.
        
        Args:
            active_only: Only return active jobs
        
        Returns:
            List of job records
        """
        cursor = self.database.connection.cursor()
        
        if active_only:
            query = "SELECT * FROM jobs WHERE is_active = 1 ORDER BY next_run" \
                if self.database.db_type == 'sqlite' else \
                "SELECT * FROM jobs WHERE is_active = TRUE ORDER BY next_run"
        else:
            query = "SELECT * FROM jobs ORDER BY created_at DESC"
        
        cursor.execute(query)
        
        jobs = []
        for row in cursor.fetchall():
            if self.database.db_type == 'sqlite':
                job = dict(row)
            else:
                columns = [desc[0] for desc in cursor.description]
                job = dict(zip(columns, row))
            jobs.append(job)
        
        return jobs
    
    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Get a job by ID."""
        cursor = self.database.connection.cursor()
        
        query = "SELECT * FROM jobs WHERE id = ?" if self.database.db_type == 'sqlite' else \
                "SELECT * FROM jobs WHERE id = %s"
        cursor.execute(query, (job_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        if self.database.db_type == 'sqlite':
            return dict(row)
        else:
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
