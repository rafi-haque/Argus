"""Contract tests for attack module interface."""
import pytest
import requests
from argus.modules.attack_modules.base import BaseAttackModule


class MockAttackModule(BaseAttackModule):
    """Mock implementation for testing."""
    
    def name(self) -> str:
        return "mock"
    
    def description(self) -> str:
        return "Mock attack module for testing"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        return True
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> list:
        return []


def test_base_attack_module_interface():
    """Test that BaseAttackModule defines the required interface."""
    config = {"test": "config"}
    module = MockAttackModule(config)
    
    # Test interface methods exist
    assert hasattr(module, 'name')
    assert hasattr(module, 'description')
    assert hasattr(module, 'check_applicable')
    assert hasattr(module, 'scan')
    
    # Test methods are callable
    assert callable(module.name)
    assert callable(module.description)
    assert callable(module.check_applicable)
    assert callable(module.scan)


def test_attack_module_name():
    """Test name() returns string."""
    module = MockAttackModule({})
    name = module.name()
    assert isinstance(name, str)
    assert len(name) > 0


def test_attack_module_description():
    """Test description() returns string."""
    module = MockAttackModule({})
    desc = module.description()
    assert isinstance(desc, str)
    assert len(desc) > 0


def test_attack_module_check_applicable():
    """Test check_applicable() with parameter and context."""
    module = MockAttackModule({})
    parameter = {'name': 'id', 'value': '5', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    result = module.check_applicable(parameter, context)
    assert isinstance(result, bool)


def test_attack_module_scan():
    """Test scan() returns list of findings."""
    module = MockAttackModule({})
    session = requests.Session()
    parameter = {'name': 'id', 'value': '5', 'location': 'query'}
    
    findings = module.scan('http://example.com', parameter, session)
    assert isinstance(findings, list)


def test_attack_module_finding_structure():
    """Test finding structure matches contract."""
    # Mock module that returns a finding
    class FindingModule(BaseAttackModule):
        def name(self):
            return "test"
        
        def description(self):
            return "Test"
        
        def check_applicable(self, parameter, context):
            return True
        
        def scan(self, url, parameter, session):
            return [{
                'name': 'Test Vulnerability',
                'severity': 'High',
                'url': url,
                'parameter': parameter['name'],
                'payload': 'test payload',
                'evidence': 'test evidence'
            }]
    
    module = FindingModule({})
    session = requests.Session()
    parameter = {'name': 'test', 'value': 'val', 'location': 'query'}
    
    findings = module.scan('http://example.com', parameter, session)
    assert len(findings) == 1
    
    finding = findings[0]
    assert 'name' in finding
    assert 'severity' in finding
    assert 'url' in finding
    assert 'parameter' in finding
    assert 'payload' in finding
    assert 'evidence' in finding
    
    assert finding['severity'] in ['High', 'Medium', 'Low', 'Info']


def test_attack_module_config_initialization():
    """Test module receives and stores config."""
    config = {'key': 'value', 'timeout': 10}
    module = MockAttackModule(config)
    
    assert module.config == config
    assert module.config['key'] == 'value'
