"""CSRF (Cross-Site Request Forgery) detection module."""
import requests
from typing import Dict, List
from bs4 import BeautifulSoup


class CSRFModule:
    """Module to detect missing CSRF protection."""
    
    def __init__(self, config: dict):
        """Initialize CSRF module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Common CSRF token names
        self.csrf_token_names = [
            'csrf_token', 'csrftoken', 'csrf', '_csrf', 'csrf_param',
            'authenticity_token', '_token', 'token', 'xsrf_token',
            'anti-csrf-token', '__requestverificationtoken'
        ]
        
        # Common CSRF header names
        self.csrf_headers = [
            'X-CSRF-Token', 'X-CSRF-TOKEN', 'X-XSRF-TOKEN',
            'X-CSRFToken', 'CSRF-Token'
        ]
    
    def name(self) -> str:
        """Return module name."""
        return 'csrf'
    
    def description(self) -> str:
        """Return module description."""
        return 'Detects missing CSRF protection on forms'
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if this module should run for given parameter.
        
        Args:
            parameter: Parameter information
            context: Request context
            
        Returns:
            bool: True if module is applicable
        """
        # CSRF check applies to POST forms
        # Only run on URL-level checks (no specific parameter)
        if parameter.get('name') is not None:
            return False
        method = context.get('method', 'GET').upper()
        return method in ['POST', 'PUT', 'DELETE', 'PATCH']
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Check for missing CSRF protection.
        
        Args:
            url: URL to check
            parameter: Parameter dict (form context)
            session: Requests session
            
        Returns:
            list: Findings for missing CSRF protection
        """
        findings = []
        
        try:
            # Get the page containing the form
            response = session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                return findings
            
            # Parse HTML to find forms
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                method = form.get('method', 'get').upper()
                
                # Only check POST/PUT/DELETE forms
                if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
                    continue
                
                action = form.get('action', '')
                
                # Check for CSRF token in form
                has_csrf_token = self._has_csrf_token(form)
                
                if not has_csrf_token:
                    # Check if endpoint expects CSRF in header
                    has_csrf_header = self._check_csrf_header_requirement(
                        url, session
                    )
                    
                    if not has_csrf_header:
                        finding = {
                            'name': 'Missing CSRF Protection',
                            'severity': 'High',
                            'url': url,
                            'parameter': 'N/A',
                            'payload': 'N/A',
                            'evidence': (
                                f'Form with method {method} and action "{action}" '
                                f'lacks CSRF token. This may allow Cross-Site '
                                f'Request Forgery attacks.'
                            ),
                            'recommendation': 'Implement CSRF tokens for all state-changing operations. Use synchronizer token pattern or double-submit cookie. Validate token on server-side for every POST/PUT/DELETE request. Set SameSite cookie attribute to Strict or Lax.'
                        }
                        findings.append(finding)
        
        except requests.exceptions.RequestException as e:
            if self.config.get('verbose'):
                print(f"Warning: Could not check CSRF for {url}: {e}")
        
        return findings
    
    def _has_csrf_token(self, form) -> bool:
        """Check if form contains a CSRF token.
        
        Args:
            form: BeautifulSoup form element
            
        Returns:
            bool: True if CSRF token found
        """
        # Check all input fields
        inputs = form.find_all('input')
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            # Check for CSRF token by name
            if name in self.csrf_token_names:
                return True
            
            # Check for hidden token fields
            if input_type == 'hidden' and 'token' in name:
                return True
        
        return False
    
    def _check_csrf_header_requirement(self, url: str, session: requests.Session) -> bool:
        """Check if endpoint requires CSRF token in header.
        
        Args:
            url: URL to check
            session: Requests session
            
        Returns:
            bool: True if CSRF header is required
        """
        try:
            # Try POST without CSRF header
            response = session.post(url, data={}, timeout=self.timeout)
            
            # If we get 403 with CSRF-related error, it's protected
            if response.status_code == 403:
                error_text = response.text.lower()
                if any(keyword in error_text for keyword in 
                       ['csrf', 'token', 'forbidden', 'invalid']):
                    return True
        
        except requests.exceptions.RequestException:
            pass
        
        return False
