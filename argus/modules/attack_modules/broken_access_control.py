"""Broken Access Control attack module - Detects IDOR and authorization issues."""
from typing import Dict, List, Optional
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .async_base import AsyncBaseAttackModule


class BrokenAccessControlModule(AsyncBaseAttackModule):
    """Detects broken access control vulnerabilities (IDOR, privilege escalation, etc)."""
    
    def __init__(self, config: dict):
        """Initialize broken access control module."""
        super().__init__(config)
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Common ID parameter names
        self.id_param_names = [
            'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
            'customer_id', 'customerid', 'order_id', 'orderid',
            'product_id', 'productid', 'item_id', 'itemid',
            'file_id', 'fileid', 'doc_id', 'docid', 'document_id',
            'profile_id', 'profileid', 'member_id', 'memberid'
        ]
        
        # Test values for IDOR detection
        self.test_ids = [
            '1', '2', '3', '999', '1000',  # Sequential IDs
            'admin', 'root', 'test', 'guest',  # Username-based IDs
            '00000000-0000-0000-0000-000000000001',  # UUID
            '00000000-0000-0000-0000-000000000002',
        ]
        
        # Sensitive data patterns in responses
        self.sensitive_patterns = [
            r'email["\']?\s*:\s*["\']([^"\']+@[^"\']+)["\']',
            r'password["\']?\s*:\s*["\']([^"\']+)["\']',
            r'ssn["\']?\s*:\s*["\'](\d{3}-?\d{2}-?\d{4})["\']',
            r'credit[_-]?card["\']?\s*:\s*["\'](\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})["\']',
            r'phone["\']?\s*:\s*["\']([+]?\d{10,})["\']',
            r'address["\']?\s*:\s*["\']([^"\']{10,})["\']',
            r'api[_-]?key["\']?\s*:\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'token["\']?\s*:\s*["\']([a-zA-Z0-9_.-]{20,})["\']',
        ]
    
    def name(self) -> str:
        """Return module name."""
        return "broken_access_control"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects broken access control (IDOR, privilege escalation, missing authorization)"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if access control testing should run on this parameter.
        
        Args:
            parameter: Parameter dict
            context: Context dict
        
        Returns:
            bool: True if this looks like an ID or resource parameter
        """
        param_name = parameter.get('name', '').lower() if parameter.get('name') else ''
        url = context.get('url', '').lower()
        
        # Check if parameter name suggests an ID
        if param_name in self.id_param_names:
            return True
        
        # Check if parameter name ends with common ID suffixes
        id_suffixes = ['id', '_id', '-id', 'Id', 'ID']
        if any(param_name.endswith(suffix) for suffix in id_suffixes):
            return True
        
        # Check if URL path suggests resource access
        resource_patterns = [
            '/user/', '/users/', '/account/', '/accounts/',
            '/profile/', '/profiles/', '/customer/', '/customers/',
            '/order/', '/orders/', '/admin/', '/api/',
            '/file/', '/files/', '/document/', '/documents/'
        ]
        
        if any(pattern in url for pattern in resource_patterns):
            return True
        
        return False
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Scan for broken access control vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: Async HTTP client
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Test IDOR (Insecure Direct Object Reference)
        idor_finding = await self._test_idor(url, parameter, client)
        if idor_finding:
            findings.append(idor_finding)
        
        # Test missing authorization checks
        authz_finding = await self._test_missing_authorization(url, parameter, client)
        if authz_finding:
            findings.append(authz_finding)
        
        # Test forced browsing to admin endpoints
        forced_finding = await self._test_forced_browsing(url, parameter, client)
        if forced_finding:
            findings.append(forced_finding)
        
        # Test mass assignment vulnerabilities
        mass_assign_finding = await self._test_mass_assignment(url, parameter, client)
        if mass_assign_finding:
            findings.append(mass_assign_finding)
        
        return findings
    
    async def _test_idor(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Optional[Dict]:
        """Test for Insecure Direct Object Reference.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter.get('name')
        param_value = parameter.get('value', '1')
        param_location = parameter.get('location', 'query')
        
        if not param_name:
            return None
        
        try:
            # Get baseline response with original ID
            baseline_response = await self._make_request(
                url, param_name, param_value, param_location, client
            )
            
            if not baseline_response or baseline_response.status_code >= 400:
                return None  # Original request failed, can't test
            
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)
            baseline_sensitive = self._extract_sensitive_data(baseline_response.text)
            
            # Try different IDs to see if we can access other resources
            for test_id in self.test_ids:
                if str(test_id) == str(param_value):
                    continue  # Skip if same as baseline
                
                try:
                    test_response = await self._make_request(
                        url, param_name, test_id, param_location, client
                    )
                    
                    if not test_response:
                        continue
                    
                    # Check if we got a successful response with different data
                    if test_response.status_code == 200:
                        test_length = len(test_response.text)
                        test_sensitive = self._extract_sensitive_data(test_response.text)
                        
                        # Check for IDOR indicators
                        length_similar = abs(test_length - baseline_length) < baseline_length * 0.3
                        has_different_data = test_sensitive and test_sensitive != baseline_sensitive
                        
                        # Strong indicator: Different sensitive data with similar structure
                        if length_similar and has_different_data:
                            evidence_parts = []
                            evidence_parts.append(f"Successfully accessed resource with ID '{test_id}' (original: '{param_value}')")
                            evidence_parts.append(f"Status: {baseline_status}→{test_response.status_code}")
                            evidence_parts.append(f"Length: {baseline_length}→{test_length}")
                            
                            if baseline_sensitive:
                                evidence_parts.append(f"Original data: {baseline_sensitive[:50]}...")
                            if test_sensitive:
                                evidence_parts.append(f"Accessed data: {test_sensitive[:50]}...")
                            
                            return {
                                'name': 'Insecure Direct Object Reference (IDOR)',
                                'severity': 'High',
                                'url': url,
                                'parameter': param_name,
                                'payload': test_id,
                                'evidence': ' | '.join(evidence_parts),
                                'recommendation': 'Implement proper authorization checks: Verify user has permission to access '
                                                'the requested resource. Use indirect references (mapping tables). Validate '
                                                'ownership of resources. Implement access control lists. Log access attempts.'
                            }
                        
                        # Weaker indicator: Just getting 200 on sequential IDs
                        elif test_response.status_code == 200 and str(test_id).isdigit():
                            return {
                                'name': 'Potential IDOR - Sequential ID Access',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': param_name,
                                'payload': test_id,
                                'evidence': f"Sequential ID '{test_id}' returned HTTP 200. "
                                          f"No authorization check detected. Manual verification recommended.",
                                'recommendation': 'Verify that proper authorization checks are in place. Users should only '
                                                'access their own resources. Implement access control validation.'
                            }
                
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing IDOR: {e}")
        
        return None
    
    async def _test_missing_authorization(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Optional[Dict]:
        """Test for missing authorization checks by removing auth headers.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        try:
            # Make request with normal headers
            auth_response = await client.get(url, timeout=self.timeout)
            
            if auth_response.status_code >= 400:
                return None  # Already blocked, can't test further
            
            # Make request without common auth headers
            headers_to_remove = [
                'Authorization', 'Cookie', 'X-Auth-Token', 'X-API-Key',
                'Api-Key', 'Access-Token', 'Bearer', 'Session'
            ]
            
            # Create a new client without auth headers
            test_headers = {k: v for k, v in client.headers.items() 
                          if k not in headers_to_remove}
            
            try:
                # Make unauthenticated request
                unauth_response = await client.get(
                    url, 
                    headers=test_headers,
                    timeout=self.timeout
                )
                
                # Check if we still got access without auth
                if unauth_response.status_code == 200:
                    # Check if response has sensitive data
                    has_sensitive = bool(self._extract_sensitive_data(unauth_response.text))
                    
                    # Check if endpoint looks like it should require auth
                    requires_auth = any(indicator in url.lower() for indicator in [
                        'admin', 'profile', 'account', 'user', 'private',
                        'dashboard', 'settings', 'api', 'order'
                    ])
                    
                    if requires_auth or has_sensitive:
                        return {
                            'name': 'Missing Authorization Check',
                            'severity': 'High',
                            'url': url,
                            'parameter': 'Authorization headers',
                            'payload': 'N/A',
                            'evidence': f"Endpoint accessible without authentication headers. "
                                      f"Auth status: {auth_response.status_code}, "
                                      f"Unauth status: {unauth_response.status_code}. "
                                      f"Sensitive data exposed: {has_sensitive}",
                            'recommendation': 'Implement proper authentication and authorization checks. Verify user identity '
                                            'and permissions on every request. Return 401/403 for unauthorized access. '
                                            'Use framework security features.'
                        }
            
            except (httpx.HTTPError, httpx.TimeoutException):
                pass  # Request failed without auth - good!
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing authorization: {e}")
        
        return None
    
    async def _test_forced_browsing(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Optional[Dict]:
        """Test for forced browsing to admin/privileged endpoints.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        try:
            parsed = urlparse(url)
            
            # Try common admin paths
            admin_paths = [
                '/admin', '/admin/', '/administrator', '/administrator/',
                '/admin/dashboard', '/admin/panel', '/admin/console',
                '/api/admin', '/api/admin/', '/backend', '/backend/',
                '/management', '/management/', '/control', '/control/',
                '/_admin', '/_admin/', '/adm', '/adm/'
            ]
            
            for admin_path in admin_paths[:5]:  # Limit tests
                try:
                    admin_url = f"{parsed.scheme}://{parsed.netloc}{admin_path}"
                    
                    response = await client.get(admin_url, timeout=self.timeout, follow_redirects=False)
                    
                    # Check if we got access
                    if response.status_code == 200:
                        # Look for admin indicators in response
                        admin_indicators = [
                            'admin panel', 'admin dashboard', 'administration',
                            'user management', 'system settings', 'control panel'
                        ]
                        
                        response_lower = response.text.lower()
                        has_admin_content = any(indicator in response_lower for indicator in admin_indicators)
                        
                        if has_admin_content:
                            return {
                                'name': 'Forced Browsing - Unauthorized Admin Access',
                                'severity': 'Critical',
                                'url': admin_url,
                                'parameter': 'URL path',
                                'payload': admin_path,
                                'evidence': f"Admin endpoint '{admin_path}' accessible without proper authorization. "
                                          f"Status: {response.status_code}. "
                                          f"Admin indicators found in response.",
                                'recommendation': 'Implement proper access control on admin endpoints. Require authentication '
                                                'and role-based authorization. Use deny-by-default approach. Log admin access.'
                            }
                
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing forced browsing: {e}")
        
        return None
    
    async def _test_mass_assignment(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Optional[Dict]:
        """Test for mass assignment vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        method = parameter.get('method', 'GET')
        
        # Only test on POST/PUT/PATCH
        if method.upper() not in ['POST', 'PUT', 'PATCH']:
            return None
        
        try:
            # Try to inject privileged fields
            privileged_fields = {
                'is_admin': 'true',
                'isAdmin': 'true',
                'admin': 'true',
                'role': 'admin',
                'user_role': 'admin',
                'userRole': 'admin',
                'permission': 'admin',
                'permissions': 'admin',
                'is_verified': 'true',
                'isVerified': 'true',
                'account_type': 'premium',
                'accountType': 'premium'
            }
            
            # Get baseline request
            baseline_response = await client.request(
                method, url, timeout=self.timeout
            )
            
            if baseline_response.status_code >= 400:
                return None
            
            # Try with privileged fields
            test_response = await client.request(
                method,
                url,
                data=privileged_fields,
                timeout=self.timeout
            )
            
            # Check if fields were accepted
            if test_response.status_code in [200, 201]:
                # Look for evidence of accepted privileged fields
                response_lower = test_response.text.lower()
                
                accepted_fields = []
                for field, value in privileged_fields.items():
                    if field.lower() in response_lower or value in response_lower:
                        accepted_fields.append(field)
                
                if accepted_fields:
                    return {
                        'name': 'Potential Mass Assignment Vulnerability',
                        'severity': 'High',
                        'url': url,
                        'parameter': ', '.join(accepted_fields[:3]),
                        'payload': str(privileged_fields),
                        'evidence': f"Privileged fields may have been accepted: {', '.join(accepted_fields)}. "
                                  f"Status: {baseline_response.status_code}→{test_response.status_code}. "
                                  f"Manual verification recommended.",
                        'recommendation': 'Use allowlist approach for input parameters. Only bind expected fields. '
                                        'Avoid binding to sensitive model attributes. Use DTOs/form objects. '
                                        'Validate and sanitize all input.'
                    }
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing mass assignment: {e}")
        
        return None
    
    async def _make_request(self, url: str, param_name: str, param_value: str, 
                           location: str, client: httpx.AsyncClient) -> Optional[httpx.Response]:
        """Make a request with the specified parameter.
        
        Args:
            url: Base URL
            param_name: Parameter name
            param_value: Parameter value
            location: Parameter location (query, body, path)
            client: HTTP client
        
        Returns:
            Response or None if failed
        """
        try:
            if location == 'query':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param_name] = [str(param_value)]
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(params, doseq=True), parsed.fragment
                ))
                return await client.get(test_url, timeout=self.timeout)
            else:
                return await client.post(url, data={param_name: param_value}, timeout=self.timeout)
        
        except (httpx.HTTPError, httpx.TimeoutException):
            return None
    
    def _extract_sensitive_data(self, text: str) -> str:
        """Extract sensitive data patterns from response text.
        
        Args:
            text: Response text
        
        Returns:
            Concatenated sensitive data found
        """
        found = []
        
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.extend(matches[:2])  # Limit to 2 matches per pattern
        
        return ' | '.join(found[:5]) if found else ''  # Max 5 total items
