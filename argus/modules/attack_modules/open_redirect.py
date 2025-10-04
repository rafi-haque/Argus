"""Open Redirect detection module."""
import httpx
from typing import Dict, List
from urllib.parse import urlparse


class OpenRedirectModule:
    """Module to detect open redirect vulnerabilities."""
    
    def __init__(self, config: dict):
        """Initialize Open Redirect module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Test redirect targets
        self.test_domains = [
            'https://evil.com',
            'http://attacker.com',
            '//evil.com',
            '///evil.com',
        ]
        
        # Encoded versions
        self.encoded_payloads = [
            'https://evil.com',
            'https%3A%2F%2Fevil.com',
            'https%253A%252F%252Fevil.com',  # Double encoded
            '//evil.com',
            '%2F%2Fevil.com',
            '@evil.com',
            'https://example.com@evil.com',
        ]
    
    def name(self) -> str:
        """Return module name."""
        return 'open_redirect'
    
    def description(self) -> str:
        """Return module description."""
        return 'Detects open redirect vulnerabilities'
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if this module should run for given parameter.
        
        Args:
            parameter: Parameter information
            context: Request context
            
        Returns:
            bool: True if module is applicable
        """
        param_name = parameter.get('name')
        if not param_name:
            return False
        param_name = param_name.lower()
        
        # Redirect-likely parameter names
        redirect_indicators = [
            'redirect', 'url', 'next', 'return', 'returnurl', 'return_url',
            'redir', 'target', 'dest', 'destination', 'continue', 'goto',
            'out', 'view', 'to', 'link', 'callback', 'return_to',
            'redirect_uri', 'redirect_url', 'forward'
        ]
        
        return any(indicator in param_name for indicator in redirect_indicators)
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Test for open redirect vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
            
        Returns:
            list: Findings
        """
        findings = []
        
        param_name = parameter['name']
        param_location = parameter['location']
        
        # Test basic payloads
        for payload in self.test_domains + self.encoded_payloads:
            try:
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                # Don't follow redirects automatically
                response = await client.get(
                    test_url,
                    timeout=self.timeout,
                    follow_redirects=False
                )
                
                # Check if redirect occurred
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirecting to our test domain
                    if self._is_external_redirect(location, url):
                        finding = {
                            'name': 'Open Redirect Vulnerability',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': (
                                f'Server redirects to external domain: {location}. '
                                f'This can be used for phishing attacks.'
                            ),
                            'recommendation': 'Validate redirect URLs against allowlist of trusted domains. Use relative URLs for internal redirects. Implement URL validation to reject external domains. Show warning page before external redirects. Avoid using user input directly in redirect targets.'
                        }
                        findings.append(finding)
                        break  # Found vulnerability
                
                # Also check for JavaScript-based redirects in response
                elif response.status_code == 200:
                    if self._check_js_redirect(response.text, payload):
                        finding = {
                            'name': 'Open Redirect Vulnerability - JavaScript',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': (
                                f'JavaScript redirect found using payload: {payload}. '
                                f'This can be used for phishing attacks.'
                            ),
                            'recommendation': 'Sanitize user input before using in JavaScript redirects. Implement URL validation on both client and server side. Use allowlist for redirect destinations. Avoid window.location assignments with user-controlled data. Consider using meta refresh with validation.'
                        }
                        findings.append(finding)
                        break
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str, location: str) -> str:
        """Inject payload into parameter.
        
        Args:
            url: Original URL
            param_name: Parameter name
            payload: Payload to inject
            location: Parameter location
            
        Returns:
            str: Modified URL
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        
        if location == 'query':
            query_params = parse_qs(parsed.query)
            query_params[param_name] = [payload]
            new_query = urlencode(query_params, doseq=True)
            
            return urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
        else:
            return url + payload
    
    def _is_external_redirect(self, location: str, original_url: str) -> bool:
        """Check if redirect location is external.
        
        Args:
            location: Redirect location
            original_url: Original URL
            
        Returns:
            bool: True if external redirect
        """
        # Parse URLs
        try:
            location_parsed = urlparse(location)
            original_parsed = urlparse(original_url)
            
            # Check if location has a different domain
            if location_parsed.netloc and location_parsed.netloc != original_parsed.netloc:
                # Check if it's one of our test domains
                if 'evil.com' in location_parsed.netloc or 'attacker.com' in location_parsed.netloc:
                    return True
            
            # Check for protocol-relative URLs (//evil.com)
            if location.startswith('//') and 'evil.com' in location:
                return True
        
        except Exception:
            pass
        
        return False
    
    def _check_js_redirect(self, html: str, payload: str) -> bool:
        """Check for JavaScript-based redirects in HTML.
        
        Args:
            html: HTML response
            payload: Test payload
            
        Returns:
            bool: True if JS redirect found with payload
        """
        html_lower = html.lower()
        payload_lower = payload.lower()
        
        # Common JavaScript redirect patterns
        js_patterns = [
            'window.location',
            'location.href',
            'location.replace',
            'location.assign',
            'document.location',
        ]
        
        # Check if payload appears in context of redirect
        for pattern in js_patterns:
            if pattern in html_lower:
                # Check if our payload is nearby
                pattern_pos = html_lower.find(pattern)
                # Check in a window around the pattern
                window_start = max(0, pattern_pos - 100)
                window_end = min(len(html_lower), pattern_pos + 200)
                window = html_lower[window_start:window_end]
                
                if 'evil.com' in window or 'attacker.com' in window:
                    return True
        
        return False
