"""Tests for HTTP utilities."""
import time
from unittest.mock import Mock, patch
from argus.http_utils import HTTPClient, ScanProgress, is_in_scope


class TestHTTPClient:
    """Tests for HTTPClient with retry logic."""
    
    def test_client_initialization(self):
        """Test client initialization with config."""
        config = {
            'performance': {
                'timeout': 15,
                'request_delay': 0.2,
                'max_retries': 5
            }
        }
        
        client = HTTPClient(config)
        
        assert client.timeout == 15
        assert client.request_delay == 0.2
        assert client.max_retries == 5
        assert client.session is not None
    
    def test_client_default_config(self):
        """Test client with default configuration."""
        client = HTTPClient({})
        
        assert client.timeout == 10
        assert client.request_delay == 0.1
        assert client.max_retries == 3
    
    def test_rate_limiting(self):
        """Test rate limiting between requests."""
        config = {'performance': {'request_delay': 0.2}}
        client = HTTPClient(config)
        
        with patch('argus.http_utils.requests.Session.get') as mock_get:
            mock_get.return_value = Mock(status_code=200)
            
            start = time.time()
            client.get('http://example.com')
            client.get('http://example.com')
            elapsed = time.time() - start
            
            # Should have delayed at least 0.2 seconds
            assert elapsed >= 0.2
    
    def test_get_request_success(self):
        """Test successful GET request."""
        client = HTTPClient({})
        
        with patch('argus.http_utils.requests.Session.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = 'Success'
            mock_get.return_value = mock_response
            
            response = client.get('http://example.com')
            
            assert response is not None
            assert response.status_code == 200
    
    def test_get_request_failure(self):
        """Test failed GET request handling."""
        client = HTTPClient({})
        
        with patch('argus.http_utils.requests.Session.get') as mock_get:
            import requests
            mock_get.side_effect = requests.exceptions.RequestException("Connection error")
            
            response = client.get('http://example.com')
            
            assert response is None


class TestScanProgress:
    """Tests for ScanProgress tracker."""
    
    def test_progress_initialization(self):
        """Test progress tracker initialization."""
        progress = ScanProgress(total_urls=100, total_params=500)
        
        assert progress.total_urls == 100
        assert progress.total_params == 500
        assert progress.scanned_urls == 0
        assert progress.tested_params == 0
        assert progress.findings_count == 0
    
    def test_update_counters(self):
        """Test updating progress counters."""
        progress = ScanProgress(total_urls=10, total_params=50)
        
        progress.update_url()
        progress.update_param()
        progress.add_finding()
        progress.add_error()
        
        assert progress.scanned_urls == 1
        assert progress.tested_params == 1
        assert progress.findings_count == 1
        assert progress.errors == 1
    
    def test_progress_percentage(self):
        """Test progress percentage calculation."""
        progress = ScanProgress(total_urls=100, total_params=500)
        
        progress.scanned_urls = 50
        assert progress.get_progress_percentage() == 50.0
        
        progress.scanned_urls = 25
        assert progress.get_progress_percentage() == 25.0
    
    def test_elapsed_time(self):
        """Test elapsed time tracking."""
        progress = ScanProgress(total_urls=10, total_params=50)
        
        time.sleep(0.1)
        elapsed = progress.get_elapsed_time()
        
        assert elapsed >= 0.1
    
    def test_get_summary(self):
        """Test progress summary generation."""
        progress = ScanProgress(total_urls=10, total_params=50)
        
        progress.scanned_urls = 5
        progress.tested_params = 25
        progress.findings_count = 3
        progress.errors = 1
        
        summary = progress.get_summary()
        
        assert summary['urls_scanned'] == 5
        assert summary['parameters_tested'] == 25
        assert summary['findings'] == 3
        assert summary['errors'] == 1
        assert 'scan_duration' in summary
        assert 'completion_percentage' in summary


class TestScopeChecking:
    """Tests for scope validation."""
    
    def test_url_in_scope_with_include_pattern(self):
        """Test URL matching include pattern."""
        scope_config = {
            'include_patterns': [r'^https?://example\.com']
        }
        
        assert is_in_scope('http://example.com/page', scope_config) is True
        assert is_in_scope('https://example.com/api', scope_config) is True
        assert is_in_scope('http://other.com/page', scope_config) is False
    
    def test_url_excluded_by_pattern(self):
        """Test URL excluded by exclude pattern."""
        scope_config = {
            'exclude_patterns': [r'/logout$', r'/admin']
        }
        
        assert is_in_scope('http://example.com/page', scope_config) is True
        assert is_in_scope('http://example.com/logout', scope_config) is False
        assert is_in_scope('http://example.com/admin/users', scope_config) is False
    
    def test_url_with_both_patterns(self):
        """Test URL with both include and exclude patterns."""
        scope_config = {
            'include_patterns': [r'^https?://example\.com'],
            'exclude_patterns': [r'/logout$']
        }
        
        assert is_in_scope('http://example.com/page', scope_config) is True
        assert is_in_scope('http://example.com/logout', scope_config) is False
        assert is_in_scope('http://other.com/page', scope_config) is False
    
    def test_url_no_patterns(self):
        """Test URL with no scope patterns (all allowed)."""
        scope_config = {}
        
        assert is_in_scope('http://example.com/page', scope_config) is True
        assert is_in_scope('http://other.com/page', scope_config) is True
