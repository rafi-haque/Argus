"""
Database schema definitions for Argus scanner.

Tables:
- scans: Metadata for each scan execution
- findings: Individual vulnerabilities discovered
- targets: Scanned targets/URLs
- jobs: Scheduled scan jobs
- users: User accounts (for multi-user setups)
"""

# SQLite schema
SQLITE_SCHEMA = """
-- Scans table: stores metadata for each scan
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    duration_seconds REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed', 'failed', 'cancelled')),
    
    -- Statistics
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    
    -- Configuration
    config_json TEXT,  -- JSON dump of scan configuration
    modules_used TEXT,  -- Comma-separated list of modules
    
    -- Metadata
    scanner_version TEXT,
    user_id INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Findings table: stores individual vulnerabilities
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    
    -- Vulnerability details
    type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    
    -- Location
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    parameter TEXT,
    
    -- Evidence
    payload TEXT,
    evidence TEXT,
    request_data TEXT,  -- JSON dump of full request
    response_data TEXT,  -- JSON dump of full response
    
    -- Compliance (if available)
    owasp_category TEXT,
    cwe_ids TEXT,  -- Comma-separated
    pci_dss_refs TEXT,  -- Comma-separated
    hipaa_refs TEXT,  -- Comma-separated
    
    -- Remediation
    remediation TEXT,
    reference_urls TEXT,  -- JSON array of reference URLs
    
    -- Metadata
    confidence REAL,  -- 0.0 to 1.0
    false_positive INTEGER DEFAULT 0,  -- Boolean flag
    verified INTEGER DEFAULT 0,  -- Boolean flag
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Targets table: stores information about scanned targets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    
    -- Discovery info
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP,
    scan_count INTEGER DEFAULT 0,
    
    -- Statistics
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    
    -- Target metadata
    title TEXT,
    technology_stack TEXT,  -- JSON array
    ip_address TEXT,
    
    -- Status
    is_active INTEGER DEFAULT 1,
    notes TEXT
);

-- Jobs table: stores scheduled scan jobs
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    
    -- Schedule
    schedule_type TEXT NOT NULL CHECK(schedule_type IN ('once', 'daily', 'weekly', 'monthly', 'cron')),
    schedule_value TEXT,  -- Cron expression or specific time
    
    -- Configuration
    config_json TEXT,  -- JSON dump of scan configuration
    modules TEXT,  -- Comma-separated list of modules
    
    -- Status
    is_active INTEGER DEFAULT 1,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    run_count INTEGER DEFAULT 0,
    
    -- Notifications
    notify_on_complete INTEGER DEFAULT 0,
    notify_on_new_findings INTEGER DEFAULT 1,
    notification_email TEXT,
    
    -- Metadata
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Users table: stores user accounts (for multi-user setups)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    
    -- Permissions
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user', 'readonly')),
    is_active INTEGER DEFAULT 1,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);
CREATE INDEX IF NOT EXISTS idx_targets_url ON targets(url);
CREATE INDEX IF NOT EXISTS idx_jobs_next_run ON jobs(next_run, is_active);
"""

# PostgreSQL schema (with minor differences)
POSTGRESQL_SCHEMA = """
-- Scans table: stores metadata for each scan
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    target_url TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    duration_seconds REAL NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('completed', 'failed', 'cancelled')),
    
    -- Statistics
    total_requests INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    
    -- Configuration
    config_json TEXT,
    modules_used TEXT,
    
    -- Metadata
    scanner_version TEXT,
    user_id INTEGER,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    
    type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    parameter TEXT,
    
    payload TEXT,
    evidence TEXT,
    request_data TEXT,
    response_data TEXT,
    
    owasp_category TEXT,
    cwe_ids TEXT,
    pci_dss_refs TEXT,
    hipaa_refs TEXT,
    
    remediation TEXT,
    reference_urls TEXT,
    
    confidence REAL,
    false_positive BOOLEAN DEFAULT FALSE,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP,
    scan_count INTEGER DEFAULT 0,
    
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    
    title TEXT,
    technology_stack TEXT,
    ip_address TEXT,
    
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    
    schedule_type TEXT NOT NULL CHECK(schedule_type IN ('once', 'daily', 'weekly', 'monthly', 'cron')),
    schedule_value TEXT,
    
    config_json TEXT,
    modules TEXT,
    
    is_active BOOLEAN DEFAULT TRUE,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    run_count INTEGER DEFAULT 0,
    
    notify_on_complete BOOLEAN DEFAULT FALSE,
    notify_on_new_findings BOOLEAN DEFAULT TRUE,
    notification_email TEXT,
    
    created_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user', 'readonly')),
    is_active BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_url ON findings(url);
CREATE INDEX IF NOT EXISTS idx_targets_url ON targets(url);
CREATE INDEX IF NOT EXISTS idx_jobs_next_run ON jobs(next_run, is_active);
"""
