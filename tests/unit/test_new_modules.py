"""Unit tests for new attack modules - CSRF, Path Traversal, Command Injection, CORS, Open Redirect."""
import pytest
import asyncio
import httpx
from unittest.mock import Mock
from argus.modules.attack_modules.csrf import CSRFModule
from argus.modules.attack_modules.path_traversal import PathTraversalModule
from argus.modules.attack_modules.command_injection import CommandInjectionModule
from argus.modules.attack_modules.cors import CORSModule
from argus.modules.attack_modules.open_redirect import OpenRedirectModule
import httpx


class TestCSRFModule:
    """Tests for CSRF detection module."""
    
    def test_module_name(self):
        """Test module name."""
        module = CSRFModule({})
        assert module.name() == 'csrf'
    
    def test_module_description(self):
        """Test module description."""
        module = CSRFModule({})
        assert 'CSRF' in module.description()
    
    def test_check_applicable_post(self):
        """Test applicability for POST requests."""
        module = CSRFModule({})
        # CSRF checks are URL-level, not parameter-level
        assert module.check_applicable(
            {'name': None, 'value': None, 'location': 'url'},
            {'url': 'http://example.com', 'method': 'POST'}
        ) is True
    
    def test_check_not_applicable_get(self):
        """Test non-applicability for GET requests."""
        module = CSRFModule({})
        assert module.check_applicable(
            {'name': None, 'value': None, 'location': 'url'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is False
    
    def test_check_not_applicable_with_parameter(self):
        """Test non-applicability when specific parameter is provided."""
        module = CSRFModule({})
        # CSRF is URL-level check, doesn't apply to specific parameters
        assert module.check_applicable(
            {'name': 'data', 'value': 'test'},
            {'url': 'http://example.com', 'method': 'POST'}
        ) is False
    
    def test_scan_with_csrf_token(self):
        """Test scan when CSRF token is present."""
        module = CSRFModule({})
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<form method="POST"><input type="hidden" name="csrf_token" value="abc123"></form>'
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        assert len(findings) == 0


class TestPathTraversalModule:
    """Tests for Path Traversal detection module."""
    
    def test_module_name(self):
        """Test module name."""
        module = PathTraversalModule({})
        assert module.name() == 'path_traversal'
    
    def test_module_description(self):
        """Test module description."""
        module = PathTraversalModule({})
        assert 'traversal' in module.description().lower()
    
    def test_check_applicable_file_param(self):
        """Test applicability for file parameters."""
        module = PathTraversalModule({})
        assert module.check_applicable(
            {'name': 'file', 'value': 'test.txt'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_applicable_path_param(self):
        """Test applicability for path parameters."""
        module = PathTraversalModule({})
        assert module.check_applicable(
            {'name': 'filepath', 'value': '/docs/readme'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_not_applicable_irrelevant_param(self):
        """Test non-applicability for irrelevant parameters."""
        module = PathTraversalModule({})
        assert module.check_applicable(
            {'name': 'username', 'value': 'test'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is False


class TestCommandInjectionModule:
    """Tests for Command Injection detection module."""
    
    def test_module_name(self):
        """Test module name."""
        module = CommandInjectionModule({})
        assert module.name() == 'command_injection'
    
    def test_module_description(self):
        """Test module description."""
        module = CommandInjectionModule({})
        assert 'command' in module.description().lower()
    
    def test_check_applicable_cmd_param(self):
        """Test applicability for command parameters."""
        module = CommandInjectionModule({})
        assert module.check_applicable(
            {'name': 'cmd', 'value': 'ls'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_applicable_ping_param(self):
        """Test applicability for ping parameters."""
        module = CommandInjectionModule({})
        assert module.check_applicable(
            {'name': 'ping', 'value': '127.0.0.1'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_not_applicable_irrelevant_param(self):
        """Test non-applicability for irrelevant parameters."""
        module = CommandInjectionModule({})
        assert module.check_applicable(
            {'name': 'username', 'value': 'test'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is False


class TestCORSModule:
    """Tests for CORS detection module."""
    
    def test_module_name(self):
        """Test module name."""
        module = CORSModule({})
        assert module.name() == 'cors'
    
    def test_module_description(self):
        """Test module description."""
        module = CORSModule({})
        assert 'CORS' in module.description()
    
    def test_check_applicable_always_true(self):
        """Test CORS is always applicable."""
        module = CORSModule({})
        assert module.check_applicable(
            {'name': 'any', 'value': 'test'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_scan_wildcard_cors(self):
        """Test detection of wildcard CORS."""
        module = CORSModule({})
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Access-Control-Allow-Origin': '*'
        }
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        assert len(findings) >= 1
        assert 'Wildcard' in findings[0]['name']
    
    def test_scan_reflected_origin(self):
        """Test detection of reflected origin."""
        module = CORSModule({})
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan('http://example.com', {}, mock_client))
        assert len(findings) >= 1
        assert 'Reflection' in findings[0]['name']


class TestOpenRedirectModule:
    """Tests for Open Redirect detection module."""
    
    def test_module_name(self):
        """Test module name."""
        module = OpenRedirectModule({})
        assert module.name() == 'open_redirect'
    
    def test_module_description(self):
        """Test module description."""
        module = OpenRedirectModule({})
        assert 'redirect' in module.description().lower()
    
    def test_check_applicable_redirect_param(self):
        """Test applicability for redirect parameters."""
        module = OpenRedirectModule({})
        assert module.check_applicable(
            {'name': 'redirect', 'value': 'http://example.com'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_applicable_next_param(self):
        """Test applicability for next parameters."""
        module = OpenRedirectModule({})
        assert module.check_applicable(
            {'name': 'next', 'value': '/dashboard'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is True
    
    def test_check_not_applicable_irrelevant_param(self):
        """Test non-applicability for irrelevant parameters."""
        module = OpenRedirectModule({})
        assert module.check_applicable(
            {'name': 'username', 'value': 'test'},
            {'url': 'http://example.com', 'method': 'GET'}
        ) is False
    
    def test_scan_detects_redirect(self):
        """Test detection of open redirect."""
        module = OpenRedirectModule({})
        
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {
            'Location': 'https://evil.com'
        }
        
        mock_client = Mock(spec=httpx.AsyncClient)
        mock_client.get.return_value = mock_response
        
        findings = asyncio.run(module.scan(
            'http://example.com?redirect=test',
            {'name': 'redirect', 'value': 'test', 'location': 'query'},
            mock_client
        ))
        
        assert len(findings) >= 1
        assert 'Redirect' in findings[0]['name']
