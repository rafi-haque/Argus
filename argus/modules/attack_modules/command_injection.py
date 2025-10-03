"""Command Injection detection module."""
import requests
import time
from typing import Dict, List


class CommandInjectionModule:
    """Module to detect OS command injection vulnerabilities."""
    
    def __init__(self, config: dict):
        """Initialize Command Injection module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Time-based detection delay (seconds)
        self.sleep_time = 5
        
        # Command injection payloads (both Unix and Windows)
        self.PAYLOADS = {
            # Unix time-based
            'unix_sleep': [
                '; sleep 5',
                '| sleep 5',
                '` sleep 5 `',
                '$( sleep 5 )',
                '|| sleep 5',
                '& sleep 5',
                '; sleep 5 #',
                '\n sleep 5',
            ],
            # Windows time-based
            'windows_timeout': [
                '; timeout /t 5',
                '| timeout /t 5',
                '& timeout /t 5',
                '&& timeout /t 5',
                '|| timeout /t 5',
            ],
            # Unix echo-based
            'unix_echo': [
                '; echo "ARGUS_CMD_INJ_TEST"',
                '| echo "ARGUS_CMD_INJ_TEST"',
                '` echo "ARGUS_CMD_INJ_TEST" `',
                '$( echo "ARGUS_CMD_INJ_TEST" )',
            ],
            # Windows echo-based
            'windows_echo': [
                '; echo ARGUS_CMD_INJ_TEST',
                '| echo ARGUS_CMD_INJ_TEST',
                '& echo ARGUS_CMD_INJ_TEST',
                '&& echo ARGUS_CMD_INJ_TEST',
            ],
        }
        
        # Unique marker for echo-based detection
        self.marker = 'ARGUS_CMD_INJ_TEST'
    
    def name(self) -> str:
        """Return module name."""
        return 'command_injection'
    
    def description(self) -> str:
        """Return module description."""
        return 'Detects OS command injection vulnerabilities'
    
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
        
        # Command-likely parameter names
        cmd_indicators = [
            'cmd', 'command', 'exec', 'execute', 'run', 'system',
            'ping', 'host', 'ip', 'domain', 'lookup', 'nslookup',
            'dig', 'shell', 'bash', 'script', 'process'
        ]
        
        return any(indicator in param_name for indicator in cmd_indicators)
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Test for command injection vulnerabilities.
        
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
        
        # Get baseline response time
        try:
            start = time.time()
            baseline_response = session.get(url, timeout=self.timeout)
            baseline_time = time.time() - start
            baseline_text = baseline_response.text
        except requests.exceptions.RequestException:
            return findings
        
        # Test time-based injection (Unix sleep)
        finding = self._test_time_based(
            url, param_name, param_location, session,
            self.PAYLOADS['unix_sleep'], baseline_time, 'Unix'
        )
        if finding:
            findings.append(finding)
            return findings  # Found, no need to test more
        
        # Test time-based injection (Windows timeout)
        finding = self._test_time_based(
            url, param_name, param_location, session,
            self.PAYLOADS['windows_timeout'], baseline_time, 'Windows'
        )
        if finding:
            findings.append(finding)
            return findings
        
        # Test echo-based injection (Unix)
        finding = self._test_echo_based(
            url, param_name, param_location, session,
            self.PAYLOADS['unix_echo'], baseline_text, 'Unix'
        )
        if finding:
            findings.append(finding)
            return findings
        
        # Test echo-based injection (Windows)
        finding = self._test_echo_based(
            url, param_name, param_location, session,
            self.PAYLOADS['windows_echo'], baseline_text, 'Windows'
        )
        if finding:
            findings.append(finding)
        
        return findings
    
    def _test_time_based(self, url: str, param_name: str, param_location: str,
                        session: requests.Session, payloads: list,
                        baseline_time: float, os_type: str) -> Dict:
        """Test time-based command injection.
        
        Args:
            url: URL to test
            param_name: Parameter name
            param_location: Parameter location
            session: Requests session
            payloads: List of payloads to test
            baseline_time: Baseline response time
            os_type: OS type (Unix/Windows)
            
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        for payload in payloads:
            try:
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                start = time.time()
                response = session.get(test_url, timeout=self.timeout + self.sleep_time + 5)
                elapsed = time.time() - start
                
                # If response took significantly longer than baseline + sleep_time
                expected_delay = self.sleep_time
                if elapsed >= (baseline_time + expected_delay - 1):  # Allow 1s tolerance
                    return {
                        'name': f'Command Injection - Time-Based ({os_type})',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': (
                            f'Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s). '
                            f'Delay of ~{self.sleep_time}s indicates command execution.'
                        ),
                        'recommendation': 'Never pass user input to system commands. Use allowlist of permitted values. Avoid shell execution - use direct API calls instead. If shell use is unavoidable, use proper escaping libraries. Implement strict input validation.'
                    }
            
            except requests.exceptions.Timeout:
                # Timeout could indicate successful injection
                return {
                    'name': f'Command Injection - Time-Based ({os_type})',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f'Request timed out (>{self.timeout}s), indicating possible command execution.',
                    'recommendation': 'Avoid executing system commands with user input. Use language-native APIs instead of shell commands. If shell use is required, properly escape all user input using shell-specific escaping functions. Implement command allowlisting.'
                }
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def _test_echo_based(self, url: str, param_name: str, param_location: str,
                        session: requests.Session, payloads: list,
                        baseline_text: str, os_type: str) -> Dict:
        """Test echo-based command injection.
        
        Args:
            url: URL to test
            param_name: Parameter name
            param_location: Parameter location
            session: Requests session
            payloads: List of payloads to test
            baseline_text: Baseline response text
            os_type: OS type (Unix/Windows)
            
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        for payload in payloads:
            try:
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                response = session.get(test_url, timeout=self.timeout)
                
                # Check if marker appears in response
                if self.marker in response.text and self.marker not in baseline_text:
                    return {
                        'name': f'Command Injection - Echo-Based ({os_type})',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': f'Marker "{self.marker}" found in response, indicating command execution.',
                        'recommendation': 'Use parameterized APIs instead of shell commands. Never concatenate user input into commands. Implement strict input validation with allowlists. Use sandboxing or containerization for command execution. Apply principle of least privilege.'
                    }
            
            except requests.exceptions.RequestException:
                continue
        
        return None
    
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
            # Append payload to existing value
            existing = query_params.get(param_name, [''])[0]
            query_params[param_name] = [existing + payload]
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
