"""Unit tests for SQLi module."""
import pytest
from argus.modules.attack_modules.sqli import SQLiModule


def test_sqli_module_name():
    """Test module name."""
    module = SQLiModule({})
    assert module.name() == "sqli"


def test_sqli_module_description():
    """Test module description."""
    module = SQLiModule({})
    desc = module.description()
    assert "sql injection" in desc.lower()


def test_check_applicable_for_id_parameter():
    """Test that SQLi applies to ID parameters."""
    module = SQLiModule({})
    parameter = {'name': 'id', 'value': '5', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_check_applicable_for_search_parameter():
    """Test that SQLi applies to search parameters."""
    module = SQLiModule({})
    parameter = {'name': 'search', 'value': 'test', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_check_applicable_for_numeric_value():
    """Test that SQLi applies to numeric values."""
    module = SQLiModule({})
    parameter = {'name': 'page', 'value': '1', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_check_not_applicable_for_irrelevant_parameter():
    """Test that SQLi doesn't apply to irrelevant parameters."""
    module = SQLiModule({})
    parameter = {'name': 'color', 'value': 'blue', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    # Should not apply (not in SQL indicator list and not numeric)
    assert module.check_applicable(parameter, context) is False


def test_payloads_defined():
    """Test that payloads are properly defined."""
    assert len(SQLiModule.BOOLEAN_PAYLOADS) > 0
    assert len(SQLiModule.TIME_PAYLOADS) > 0
    
    # Check boolean payloads come in pairs
    for true_payload, false_payload in SQLiModule.BOOLEAN_PAYLOADS:
        assert isinstance(true_payload, str)
        assert isinstance(false_payload, str)
        assert len(true_payload) > 0
        assert len(false_payload) > 0
