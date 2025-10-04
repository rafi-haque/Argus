"""Additional unit tests for attack modules - comprehensive coverage."""
import pytest
from unittest.mock import Mock, patch
from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
from argus.modules.attack_modules.sqli import SQLiModule
from argus.modules.attack_modules.xss import XSSModule
import asyncio
import httpx


class TestInsecureHeadersComprehensive:
    """Comprehensive tests for Insecure Headers module."""
    
    def test_scan_with_all_headers_present(self):
        """Test when all security headers are present."""
        config = {}
        module = InsecureHeadersModule(config)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=()',
            'X-XSS-Protection': '1; mode=block'
        }
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        assert len(findings) == 0
    
    def test_scan_with_missing_headers(self):
        """Test when some headers are missing."""
        config = {}
        module = InsecureHeadersModule(config)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'X-Frame-Options': 'SAMEORIGIN'
        }
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        assert len(findings) == 6  # 7 total - 1 present
    
    def test_scan_handles_connection_error(self):
        """Test handling of connection errors."""
        config = {}
        module = InsecureHeadersModule(config)
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.side_effect = httpx.HTTPError("Connection refused")
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        
        assert len(findings) == 0


class TestSQLiComprehensive:
    """Comprehensive tests for SQLi module."""
    
    def test_boolean_sqli_detection(self):
        """Test Boolean-based SQLi detection."""
        config = {}
        module = SQLiModule(config)
        
        parameter = {'name': 'id', 'value': '1', 'location': 'query'}
        
        baseline_response = Mock()
        baseline_response.status_code = 200
        baseline_response.text = "Product 1"
        baseline_response.headers = {}
        baseline_response.content = b"Product 1"
        baseline_response.elapsed.total_seconds.return_value = 0.1
        
        # Make true response much larger (>100 bytes difference)
        large_text = "Product 1 " * 50
        true_response = Mock()
        true_response.status_code = 200
        true_response.text = large_text
        true_response.headers = {}
        true_response.content = large_text.encode()
        true_response.elapsed.total_seconds.return_value = 0.1
        
        false_response = Mock()
        false_response.status_code = 200
        false_response.text = "Product 1"
        false_response.headers = {}
        false_response.content = b"Product 1"
        false_response.elapsed.total_seconds.return_value = 0.1
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.side_effect = [baseline_response, true_response, false_response] * 10
        
        findings = asyncio.run(module.scan('http://example.com?id=1', parameter, mock_client))
        assert len(findings) == 1
        assert 'Boolean' in findings[0]['name']
        assert findings[0]['severity'] == 'High'
    
    def test_check_applicable_for_different_parameters(self):
        """Test applicability checks for various parameter types."""
        config = {}
        module = SQLiModule(config)
        
        assert module.check_applicable(
            {'name': 'id', 'value': '1', 'location': 'query'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
        
        assert module.check_applicable(
            {'name': 'user_id', 'value': '123', 'location': 'query'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True


class TestXSSComprehensive:
    """Comprehensive tests for XSS module."""
    
    def test_reflected_xss_detection(self):
        """Test Reflected XSS detection."""
        config = {}
        module = XSSModule(config)
        
        parameter = {'name': 'q', 'value': 'test', 'location': 'query'}
        
        import hashlib
        unique_id = hashlib.md5(b"http://example.com?q=testq").hexdigest()[:8]
        
        # Use string concatenation to avoid f-string issues
        response_text = "<html><div>Search for: <script>argus_xss_" + unique_id + "</script></div></html>"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = response_text
        mock_response.headers = {}
        mock_response.content = response_text.encode()
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com?q=test', parameter, mock_client))
        reflected = [f for f in findings if 'Reflected' in f['name']]
        assert len(reflected) >= 1
        assert reflected[0]['severity'] == 'High'
    
    def test_xss_not_detected_when_encoded(self):
        """Test that properly encoded output does not trigger XSS."""
        config = {}
        module = XSSModule(config)
        
        parameter = {'name': 'q', 'value': 'test', 'location': 'query'}
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<html><div>Search for: &lt;script&gt;alert(1)&lt;/script&gt;</div></html>'
        mock_response.headers = {}
        mock_response.content = b'<html><div>Search for: &lt;script&gt;alert(1)&lt;/script&gt;</div></html>'
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com?q=test', parameter, mock_client))
        reflected = [f for f in findings if 'Reflected' in f['name']]
        assert len(reflected) == 0
    
    def test_check_applicable_for_parameters(self):
        """Test XSS applicability for different parameters."""
        config = {}
        module = XSSModule(config)
        
        assert module.check_applicable(
            {'name': 'search', 'value': 'test', 'location': 'query'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
        
        assert module.check_applicable(
            {'name': 'comment', 'value': 'test', 'location': 'body'},
            {'url': 'http://example.com', 'method': 'POST'}
        ) is True


class TestModuleIntegration:
    """Integration tests for multiple modules working together."""
    
    def test_all_modules_can_be_instantiated(self):
        """Test that all modules can be created."""
        config = {}
        
        headers_module = InsecureHeadersModule(config)
        sqli_module = SQLiModule(config)
        xss_module = XSSModule(config)
        
        assert headers_module.name() == 'insecure_headers'
        assert sqli_module.name() == 'sqli'
        assert xss_module.name() == 'xss'
