"""Unit tests for Reporting module."""
import pytest
import json
from io import StringIO
import sys
from argus.modules.reporting import CLIReporter, JSONReporter


def test_cli_reporter_initialization():
    """Test CLI reporter initialization."""
    reporter = CLIReporter({})
    assert reporter is not None


def test_cli_reporter_severity_color():
    """Test severity color mapping."""
    reporter = CLIReporter({})
    
    # Test different severity levels with colorize method
    high_text = reporter._colorize('HIGH', 'High')
    assert '\033[91m' in high_text  # Red color code
    
    medium_text = reporter._colorize('MEDIUM', 'Medium')
    assert '\033[93m' in medium_text  # Yellow
    
    low_text = reporter._colorize('LOW', 'Low')
    assert '\033[94m' in low_text  # Blue
    
    info_text = reporter._colorize('INFO', 'Info')
    assert '\033[96m' in info_text  # Cyan


def test_cli_reporter_has_colors():
    """Test that reporter has color definitions."""
    reporter = CLIReporter({})
    
    assert hasattr(reporter, 'COLORS')
    assert 'High' in reporter.COLORS
    assert 'Medium' in reporter.COLORS
    assert 'Low' in reporter.COLORS
    assert 'Info' in reporter.COLORS


def test_json_reporter_initialization():
    """Test JSON reporter initialization."""
    reporter = JSONReporter({})
    assert reporter is not None


def test_json_reporter_generate_report():
    """Test JSON report generation."""
    reporter = JSONReporter({})
    
    findings = [
        {
            'module': 'sqli',
            'severity': 'High',
            'name': 'SQL Injection',
            'url': 'http://example.com/page',
            'parameter': 'id',
            'payload': "' OR '1'='1",
            'evidence': 'SQL error in response'
        },
        {
            'module': 'xss',
            'severity': 'Medium',
            'name': 'XSS',
            'url': 'http://example.com/search',
            'parameter': 'q',
            'payload': '<script>alert(1)</script>',
            'evidence': 'Script reflected in response'
        }
    ]
    
    site_map = [
        {'url': 'http://example.com/', 'method': 'GET'},
        {'url': 'http://example.com/page', 'method': 'GET'}
    ]
    
    stats = {
        'urls_scanned': 2,
        'parameters_tested': 5,
        'modules_run': 2,
        'scan_duration': 1.5,
        'errors': 0
    }
    
    report = reporter.generate_report(findings, site_map, stats)
    
    # Validate JSON structure
    assert 'scan_info' in report
    assert 'findings' in report
    assert len(report['findings']) == 2
    assert 'summary' in report
    assert report['summary']['total'] == 2


def test_json_reporter_severity_counts():
    """Test JSON report severity counting."""
    reporter = JSONReporter({})
    
    findings = [
        {'severity': 'High', 'name': 'Test1', 'url': 'http://test.com', 'parameter': 'id', 'payload': 'test', 'evidence': 'test'},
        {'severity': 'High', 'name': 'Test2', 'url': 'http://test.com', 'parameter': 'id', 'payload': 'test', 'evidence': 'test'},
        {'severity': 'Medium', 'name': 'Test3', 'url': 'http://test.com', 'parameter': 'id', 'payload': 'test', 'evidence': 'test'},
        {'severity': 'Low', 'name': 'Test4', 'url': 'http://test.com', 'parameter': 'id', 'payload': 'test', 'evidence': 'test'}
    ]
    
    stats = {'urls_scanned': 1, 'parameters_tested': 1, 'modules_run': 1, 'scan_duration': 1.0, 'errors': 0}
    
    report = reporter.generate_report(findings, [], stats)
    
    assert report['summary']['by_severity']['High'] == 2
    assert report['summary']['by_severity']['Medium'] == 1
    assert report['summary']['by_severity']['Low'] == 1


def test_json_reporter_output_format():
    """Test JSON output format."""
    reporter = JSONReporter({})
    
    findings = [
        {
            'module': 'sqli',
            'severity': 'High',
            'name': 'SQL Injection',
            'url': 'http://example.com/page',
            'parameter': 'id',
            'payload': "' OR '1'='1",
            'evidence': 'SQL error'
        }
    ]
    
    site_map = [{'url': 'http://example.com/', 'method': 'GET'}]
    stats = {'urls_scanned': 1, 'parameters_tested': 1, 'modules_run': 1, 'scan_duration': 1.0, 'errors': 0}
    
    report = reporter.generate_report(findings, site_map, stats)
    
    # Ensure it's valid JSON
    json_str = json.dumps(report, indent=2)
    parsed = json.loads(json_str)
    
    assert 'scan_info' in parsed
    assert len(parsed['findings']) == 1
    assert parsed['findings'][0]['severity'] == 'High'
