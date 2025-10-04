"""
Argus Database Layer

Provides persistent storage for scan results, trend analysis, and scheduling.
Supports both SQLite (single-user) and PostgreSQL (multi-user) backends.
"""

from argus.database.storage import ScanDatabase
from argus.database.scheduler import ScanScheduler

__all__ = ['ScanDatabase', 'ScanScheduler']
