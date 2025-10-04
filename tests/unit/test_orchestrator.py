"""Unit tests for Orchestrator module."""
import pytest
from argus.modules.orchestrator import ScannerOrchestrator


def test_orchestrator_initialization():
    """Test orchestrator initialization."""
    config = {'performance': {'max_concurrent': 5}}
    orchestrator = ScannerOrchestrator(config, [])
    
    assert orchestrator.config == config
    assert orchestrator.modules == []


def test_orchestrator_with_modules():
    """Test orchestrator with attack modules."""
    from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
    
    config = {}
    modules = [InsecureHeadersModule(config)]
    orchestrator = ScannerOrchestrator(config, modules)
    
    assert len(orchestrator.modules) == 1
    assert orchestrator.modules[0].name() == "insecure_headers"


def test_apply_contextual_rules_login_form():
    """Test contextual rules for login forms."""
    from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
    from argus.modules.attack_modules.sqli import SQLiModule
    from argus.modules.attack_modules.xss import XSSModule
    
    config = {}
    modules = [InsecureHeadersModule(config), SQLiModule(config), XSSModule(config)]
    orchestrator = ScannerOrchestrator(config, modules)
    
    parameter = {
        'name': 'username',
        'value': '',
        'location': 'body'
    }
    context = {
        'url': 'http://example.com/login',
        'method': 'POST',
        'all_params': [
            {'name': 'username', 'location': 'body'},
            {'name': 'password', 'location': 'body'}
        ]
    }
    
    result = orchestrator._apply_contextual_rules(parameter, context)
    
    # Login forms should prioritize SQLi over XSS
    assert 'sqli' in result


def test_apply_contextual_rules_api_endpoint():
    """Test contextual rules for API endpoints."""
    from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
    from argus.modules.attack_modules.sqli import SQLiModule
    from argus.modules.attack_modules.xss import XSSModule
    
    config = {}
    modules = [InsecureHeadersModule(config), SQLiModule(config), XSSModule(config)]
    orchestrator = ScannerOrchestrator(config, modules)
    
    parameter = {
        'name': 'id',
        'value': '123',
        'location': 'query'
    }
    context = {
        'url': 'http://example.com/api/users',
        'method': 'GET',
        'all_params': []
    }
    
    result = orchestrator._apply_contextual_rules(parameter, context)
    
    # API endpoints should prioritize SQLi
    assert 'sqli' in result


def test_apply_contextual_rules_search_form():
    """Test contextual rules for search forms."""
    from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
    from argus.modules.attack_modules.sqli import SQLiModule
    from argus.modules.attack_modules.xss import XSSModule
    
    config = {}
    modules = [InsecureHeadersModule(config), SQLiModule(config), XSSModule(config)]
    orchestrator = ScannerOrchestrator(config, modules)
    
    parameter = {
        'name': 'q',
        'value': '',
        'location': 'query'
    }
    context = {
        'url': 'http://example.com/search',
        'method': 'GET',
        'all_params': []
    }
    
    result = orchestrator._apply_contextual_rules(parameter, context)
    
    # Search endpoints should prioritize XSS
    assert 'xss' in result
