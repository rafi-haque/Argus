"""Unit tests for XSS module."""
from argus.modules.attack_modules.xss import XSSModule


def test_xss_module_name():
    """Test module name."""
    module = XSSModule({})
    assert module.name() == "xss"


def test_xss_module_description():
    """Test module description."""
    module = XSSModule({})
    desc = module.description()
    assert "xss" in desc.lower() or "cross-site scripting" in desc.lower()


def test_check_applicable_for_query_parameter():
    """Test that XSS applies to query parameters."""
    module = XSSModule({})
    parameter = {'name': 'search', 'value': 'test', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_check_applicable_for_body_parameter():
    """Test that XSS applies to body parameters."""
    module = XSSModule({})
    parameter = {'name': 'comment', 'value': 'test', 'location': 'body'}
    context = {'url': 'http://example.com', 'method': 'POST', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_check_not_applicable_for_url_parameter():
    """Test that XSS doesn't apply to URL-level parameters."""
    module = XSSModule({})
    parameter = {'name': None, 'value': None, 'location': 'url'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is False
