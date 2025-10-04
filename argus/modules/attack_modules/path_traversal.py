"""Path Traversal / Directory Traversal detection module."""
import httpx
from typing import Dict, List
from urllib.parse import urlparse


class PathTraversalModule:
    """Module to detect path traversal vulnerabilities."""
    
    def __init__(self, config: dict):
        """Initialize Path Traversal module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Path traversal payloads
        self.PAYLOADS = [
            # Basic traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            
            # URL encoded
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5c%77%69%6e%64%6f%77%73%5c%77%69%6e%2e%69%6e%69',
            
            # Double encoded
            '%252e%252e%252f%252e%252e%252f%252e%252e%252f%65%74%63%2f%70%61%73%73%77%64',
            
            # Null byte injection (legacy systems)
            '../../../etc/passwd%00',
            
            # Absolute paths
            '/etc/passwd',
            'C:\\windows\\win.ini',
            
            # Mixed encoding
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%5c..%5c..%5cwindows%5cwin.ini',
            
            # Unicode variants
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            
            # Bypass filters
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\win.ini',
        ]
        
        # Evidence markers for successful traversal
        self.UNIX_MARKERS = [
            'root:x:', 'daemon:', 'bin:', '/bin/bash', '/bin/sh',
            'nobody:', 'www-data:'
        ]
        
        self.WINDOWS_MARKERS = [
            '[fonts]', '[extensions]', '[mci extensions]',
            'MAPI=1', 'for 16-bit app support'
        ]
    
    def name(self) -> str:
        """Return module name."""
        return 'path_traversal'
    
    def description(self) -> str:
        """Return module description."""
        return 'Detects path traversal / directory traversal vulnerabilities'
    
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
        
        # Likely file/path parameters
        file_indicators = [
            'file', 'path', 'dir', 'folder', 'document', 'doc',
            'page', 'template', 'include', 'load', 'read',
            'download', 'upload', 'view', 'show', 'filename'
        ]
        
        return any(indicator in param_name for indicator in file_indicators)
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Test for path traversal vulnerabilities.
        
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
        
        # Get baseline response
        try:
            baseline_response = session.get(url, timeout=self.timeout)
            baseline_text = baseline_response.text
            baseline_size = len(baseline_response.content)
        except (httpx.HTTPError, httpx.TimeoutException):
            return findings
        
        # Test each payload
        for payload in self.PAYLOADS:
            try:
                # Inject payload
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                # Make request
                response = await client.get(test_url, timeout=self.timeout)
                
                # Check for successful traversal
                is_vulnerable, evidence = self._check_traversal_success(
                    response.text,
                    baseline_text
                )
                
                if is_vulnerable:
                    finding = {
                        'name': 'Path Traversal Vulnerability',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence,
                        'recommendation': 'Never pass user input directly to file system operations. Use allowlist of permitted files/paths. Validate and sanitize file paths. Use secure APIs that prevent directory traversal (e.g., Path.GetFullPath() validation). Implement proper access controls.'
                    }
                    findings.append(finding)
                    break  # Found vulnerability, no need to test more
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return findings
    
    def _inject_payload(self, url: str, param_name: str, payload: str, location: str) -> str:
        """Inject payload into parameter.
        
        Args:
            url: Original URL
            param_name: Parameter name
            payload: Payload to inject
            location: Parameter location (query/path)
            
        Returns:
            str: Modified URL
        """
        from urllib.parse import parse_qs, urlencode, urlunparse
        
        parsed = urlparse(url)
        
        if location == 'query':
            # Modify query parameter
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
            # For path parameters, replace in path
            return url.replace(param_name, payload)
    
    def _check_traversal_success(self, response_text: str, baseline_text: str) -> tuple:
        """Check if path traversal was successful.
        
        Args:
            response_text: Response text
            baseline_text: Baseline response text
            
        Returns:
            tuple: (is_vulnerable, evidence)
        """
        # Check for Unix file markers
        for marker in self.UNIX_MARKERS:
            if marker in response_text and marker not in baseline_text:
                return True, f'Unix system file exposed: Found "{marker}" in response'
        
        # Check for Windows file markers
        for marker in self.WINDOWS_MARKERS:
            if marker in response_text and marker not in baseline_text:
                return True, f'Windows system file exposed: Found "{marker}" in response'
        
        # Check for common error messages that indicate file access attempt
        error_indicators = [
            'Permission denied',
            'Access is denied',
            'No such file or directory',
            'File not found',
            'FileNotFoundException'
        ]
        
        for indicator in error_indicators:
            if indicator in response_text and indicator not in baseline_text:
                # This suggests the server is attempting file access
                return True, f'Path traversal attempt detected: {indicator}'
        
        return False, ''
