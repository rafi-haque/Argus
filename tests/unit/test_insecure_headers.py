"""Unit tests for insecure headers module."""
from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule


def test_insecure_headers_module_name():
    """Test module name."""
    module = InsecureHeadersModule({})
    assert module.name() == "insecure_headers"


def test_insecure_headers_module_description():
    """Test module description."""
    module = InsecureHeadersModule({})
    desc = module.description()
    assert "security headers" in desc.lower()


def test_check_applicable_always_true():
    """Test that headers module applies to all URLs."""
    module = InsecureHeadersModule({})
    parameter = {'name': 'test', 'value': 'val', 'location': 'query'}
    context = {'url': 'http://example.com', 'method': 'GET', 'all_params': []}
    
    assert module.check_applicable(parameter, context) is True


def test_security_headers_defined():
    """Test that security headers are properly defined."""
    assert len(InsecureHeadersModule.SECURITY_HEADERS) > 0
    
    # Check some expected headers
    assert 'Content-Security-Policy' in InsecureHeadersModule.SECURITY_HEADERS
    assert 'Strict-Transport-Security' in InsecureHeadersModule.SECURITY_HEADERS
    assert 'X-Frame-Options' in InsecureHeadersModule.SECURITY_HEADERS
    
    # Check header info structure
    for header_name, header_info in InsecureHeadersModule.SECURITY_HEADERS.items():
        assert 'severity' in header_info
        assert 'description' in header_info
        assert header_info['severity'] in ['High', 'Medium', 'Low', 'Info']
