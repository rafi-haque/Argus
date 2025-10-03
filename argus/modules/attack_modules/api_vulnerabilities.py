"""API-specific vulnerabilities detection module."""
from argus.modules.attack_modules.base import BaseAttackModule
import json


class APIVulnerabilitiesModule(BaseAttackModule):
    """Detects API-specific vulnerabilities.
    
    Focuses on OWASP API Security Top 10:
    - Broken Object Level Authorization (BOLA/IDOR)
    - Mass Assignment
    - Excessive Data Exposure
    - Security Misconfiguration
    """
    
    # Common ID-like parameter names
    ID_PARAMETERS = [
        'id', 'user_id', 'userid', 'user', 'account_id', 'accountid',
        'object_id', 'objectid', 'item_id', 'product_id', 'order_id',
        'profile_id', 'document_id', 'file_id', 'customer_id', 'client_id'
    ]
    
    # Mass assignment test fields
    MASS_ASSIGNMENT_FIELDS = [
        'is_admin', 'isAdmin', 'admin', 'is_superuser', 'role', 'roles',
        'permissions', 'permission', 'is_active', 'isActive', 'active',
        'verified', 'is_verified', 'approved', 'is_approved', 'status',
        'privilege', 'privileges', 'level', 'access', 'account_type'
    ]
    
    def name(self) -> str:
        """Return module name."""
        return "api_vulnerabilities"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects API-specific vulnerabilities like BOLA, Mass Assignment, Data Exposure"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if API vulnerability testing applies.
        
        Args:
            parameter: Parameter dict with 'name', 'value', 'location'
            context: Context dict with 'url', 'method', 'all_params'
        
        Returns:
            bool: True if this module should test the parameter
        """
        url = context.get('url', '').lower()
        param_name = parameter.get('name', '')
        
        # Check if it's an API endpoint
        is_api = (
            '/api/' in url or
            'api.' in url or
            '.json' in url or
            'graphql' in url
        )
        
        if not is_api:
            return False
        
        # Only test ID parameters for BOLA
        if param_name and param_name.lower() in [p.lower() for p in self.ID_PARAMETERS]:
            return True
        
        # Test all parameters for Mass Assignment on write operations
        method = context.get('method', 'GET').upper()
        if method in ['POST', 'PUT', 'PATCH'] and param_name:
            return True
        
        # Test URL-level for general API issues
        if param_name is None:
            return True
        
        return False
    
    def scan(self, url: str, parameter: dict, session) -> list:
        """Scan for API vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            # Test for BOLA/IDOR
            if parameter.get('name') and parameter['name'].lower() in [p.lower() for p in self.ID_PARAMETERS]:
                findings.extend(self._test_bola(url, parameter, session))
            
            # Test for Mass Assignment (POST/PUT/PATCH)
            # This is URL-level, not parameter-level
            if not parameter.get('name'):
                findings.extend(self._test_mass_assignment(url, parameter, session))
                findings.extend(self._test_excessive_data_exposure(url, parameter, session))
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error in API vulnerabilities module: {e}")
        
        return findings
    
    def _test_bola(self, url: str, parameter: dict, session) -> list:
        """Test for Broken Object Level Authorization (BOLA/IDOR).
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            # Get response with original ID
            original_params = {parameter['name']: parameter['value']}
            original_response = session.get(url, params=original_params, timeout=self.timeout)
            
            if original_response.status_code != 200:
                return findings  # Original request failed, can't test
            
            original_length = len(original_response.text)
            
            # Try common ID manipulation techniques
            original_id = str(parameter['value'])
            test_ids = []
            
            # Numeric ID
            if original_id.isdigit():
                num = int(original_id)
                test_ids = [
                    str(num - 1),
                    str(num + 1),
                    str(num - 10),
                    str(num + 10),
                    '1',
                    '2',
                    '99999',
                ]
            # UUID-like
            elif len(original_id) > 20 and '-' in original_id:
                test_ids = [
                    '00000000-0000-0000-0000-000000000001',
                    '11111111-1111-1111-1111-111111111111',
                ]
            # Other string IDs
            else:
                test_ids = ['admin', 'test', 'user1', '1']
            
            for test_id in test_ids[:5]:  # Limit tests
                try:
                    test_params = {parameter['name']: test_id}
                    response = session.get(url, params=test_params, timeout=self.timeout)
                    
                    # Check if we got a successful response with different data
                    if response.status_code == 200:
                        # Response should be different from original
                        if response.text != original_response.text:
                            # But similar in size (indicates valid data)
                            size_diff = abs(len(response.text) - original_length)
                            if size_diff < original_length * 0.5:  # Within 50% of original
                                findings.append({
                                    'name': 'Broken Object Level Authorization (BOLA/IDOR)',
                                    'severity': 'High',
                                    'url': url,
                                    'parameter': parameter['name'],
                                    'payload': test_id,
                                    'evidence': f'Able to access object with ID "{test_id}" (original: "{original_id}")',
                                    'recommendation': 'Implement proper authorization checks. Verify that the authenticated user has permission to access the requested object. Use indirect references or add authorization middleware.'
                                })
                                return findings  # Found BOLA, stop testing
                
                except Exception:
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing BOLA: {e}")
        
        return findings
    
    def _test_mass_assignment(self, url: str, parameter: dict, session) -> list:
        """Test for Mass Assignment vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            # Only test on write operations
            # Since this is URL-level, we need to check the URL for HTTP method
            # For now, just do basic POST testing
            
            # Try adding privileged fields to request
            for field in self.MASS_ASSIGNMENT_FIELDS[:5]:  # Test first 5
                try:
                    # Test with JSON
                    test_data = {field: True, 'test': 'value'}
                    response = session.post(
                        url,
                        json=test_data,
                        timeout=self.timeout
                    )
                    
                    # Check if field was accepted (no error about unknown field)
                    response_lower = response.text.lower()
                    
                    # Positive indicators (field accepted)
                    accepted_indicators = [
                        f'"{field}"',
                        f"'{field}'",
                        field.lower(),
                    ]
                    
                    # Negative indicators (field rejected)
                    rejected_indicators = [
                        'unknown field',
                        'invalid field',
                        'unexpected field',
                        'not allowed',
                        'forbidden',
                    ]
                    
                    field_mentioned = any(ind in response_lower for ind in accepted_indicators)
                    field_rejected = any(ind in response_lower for ind in rejected_indicators)
                    
                    # If field mentioned but not rejected, possible mass assignment
                    if field_mentioned and not field_rejected and response.status_code in [200, 201]:
                        findings.append({
                            'name': 'Potential Mass Assignment',
                            'severity': 'High',
                            'url': url,
                            'parameter': field,
                            'payload': json.dumps(test_data),
                            'evidence': f'Privileged field "{field}" accepted without rejection',
                            'recommendation': 'Implement strict property allowlists. Only allow specific fields to be set by users. Use DTOs or form objects to define allowed fields explicitly.'
                        })
                        return findings  # Found one, that's enough
                
                except Exception:
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing Mass Assignment: {e}")
        
        return findings
    
    def _test_excessive_data_exposure(self, url: str, parameter: dict, session) -> list:
        """Test for Excessive Data Exposure.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            response = session.get(url, timeout=self.timeout)
            
            if response.status_code != 200:
                return findings
            
            # Check if response is JSON
            try:
                data = response.json()
            except:
                return findings  # Not JSON
            
            # Look for sensitive fields in response
            sensitive_fields = [
                'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
                'apikey', 'private_key', 'privatekey', 'ssn', 'social_security',
                'credit_card', 'creditcard', 'card_number', 'cvv', 'pin',
                'hash', 'salt', 'internal', 'admin_note', 'note'
            ]
            
            def check_dict_for_sensitive(obj, path=''):
                """Recursively check dict for sensitive fields."""
                found_fields = []
                
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        current_path = f"{path}.{key}" if path else key
                        key_lower = key.lower()
                        
                        # Check if key name is sensitive
                        if any(sensitive in key_lower for sensitive in sensitive_fields):
                            # Check if value is not empty/null
                            if value and str(value).lower() not in ['null', 'none', '']:
                                found_fields.append((current_path, str(value)[:50]))
                        
                        # Recurse
                        found_fields.extend(check_dict_for_sensitive(value, current_path))
                
                elif isinstance(obj, list):
                    for i, item in enumerate(obj[:5]):  # Check first 5 items
                        found_fields.extend(check_dict_for_sensitive(item, f"{path}[{i}]"))
                
                return found_fields
            
            exposed_fields = check_dict_for_sensitive(data)
            
            if exposed_fields:
                field_names = [f[0] for f in exposed_fields[:3]]  # First 3
                findings.append({
                    'name': 'Excessive Data Exposure',
                    'severity': 'Medium',
                    'url': url,
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'evidence': f'Sensitive fields exposed in API response: {", ".join(field_names)}',
                    'recommendation': 'Filter response data. Only return fields necessary for the client. Use DTOs or serializers to explicitly define which fields to expose. Never include sensitive fields like passwords, tokens, or keys in responses.'
                })
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing Excessive Data Exposure: {e}")
        
        return findings
