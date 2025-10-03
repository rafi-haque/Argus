"""CORS (Cross-Origin Resource Sharing) misconfiguration detection module."""
import requests
from typing import Dict, List


class CORSModule:
    """Module to detect CORS misconfigurations."""
    
    def __init__(self, config: dict):
        """Initialize CORS module.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        
        # Test origins
        self.test_origins = [
            'https://evil.com',
            'http://attacker.com',
            'null',
        ]
    
    def name(self) -> str:
        """Return module name."""
        return 'cors'
    
    def description(self) -> str:
        """Return module description."""
        return 'Detects CORS misconfigurations'
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if this module should run.
        
        Args:
            parameter: Parameter information
            context: Request context
            
        Returns:
            bool: True if module is applicable (always check CORS)
        """
        # CORS is a URL-level check, always applicable
        return True
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Check for CORS misconfigurations.
        
        Args:
            url: URL to check
            parameter: Parameter dict (ignored)
            session: Requests session
            
        Returns:
            list: Findings for CORS issues
        """
        findings = []
        
        try:
            # Test with various origins
            for test_origin in self.test_origins:
                headers = {
                    'Origin': test_origin
                }
                
                response = session.get(url, headers=headers, timeout=self.timeout)
                
                # Check CORS headers in response
                acao = response.headers.get('Access-Control-Allow-Origin')
                acac = response.headers.get('Access-Control-Allow-Credentials')
                
                if acao:
                    # Check for overly permissive CORS
                    if acao == '*':
                        if acac and acac.lower() == 'true':
                            # Critical: Wildcard with credentials
                            finding = {
                                'name': 'CORS Misconfiguration - Wildcard with Credentials',
                                'severity': 'Critical',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': f'Origin: {test_origin}',
                                'evidence': (
                                    'Access-Control-Allow-Origin: * with '
                                    'Access-Control-Allow-Credentials: true. '
                                    'This allows any origin to make credentialed requests.'
                                ),
                                'recommendation': 'Never use Access-Control-Allow-Origin: * with credentials. Specify exact allowed origins. Validate Origin header on server-side. Use allowlist of trusted domains. Remove Access-Control-Allow-Credentials if not needed.'
                            }
                            findings.append(finding)
                        else:
                            # Medium: Wildcard without credentials
                            finding = {
                                'name': 'CORS Misconfiguration - Wildcard Origin',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': f'Origin: {test_origin}',
                                'evidence': (
                                    'Access-Control-Allow-Origin: * allows any origin '
                                    'to read responses. Consider restricting to specific origins.'
                                ),
                                'recommendation': 'Replace wildcard (*) with specific trusted origins. Implement origin validation on server-side. Use allowlist of approved domains. Consider if CORS is necessary for your use case.'
                            }
                            findings.append(finding)
                    
                    elif acao == test_origin:
                        # High: Reflects arbitrary origin
                        if acac and acac.lower() == 'true':
                            finding = {
                                'name': 'CORS Misconfiguration - Arbitrary Origin Reflection',
                                'severity': 'High',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': f'Origin: {test_origin}',
                                'evidence': (
                                    f'Server reflects arbitrary origin "{test_origin}" with '
                                    f'credentials enabled. This allows any origin to make '
                                    f'credentialed requests.'
                                ),
                                'recommendation': 'Implement strict origin validation. Use allowlist of exact trusted origins. Never reflect arbitrary origins with credentials. Validate Origin header against known safe values before setting CORS headers.'
                            }
                            findings.append(finding)
                        else:
                            finding = {
                                'name': 'CORS Misconfiguration - Origin Reflection',
                                'severity': 'Medium',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': f'Origin: {test_origin}',
                                'evidence': (
                                    f'Server reflects arbitrary origin "{test_origin}". '
                                    f'This may allow unauthorized cross-origin access.'
                                ),
                                'recommendation': 'Validate Origin header before reflection. Maintain allowlist of approved origins. Reject requests from untrusted origins. Consider using specific origin values instead of dynamic reflection.'
                            }
                            findings.append(finding)
                    
                    elif acao == 'null' and test_origin == 'null':
                        # Medium: null origin allowed
                        finding = {
                            'name': 'CORS Misconfiguration - Null Origin Allowed',
                            'severity': 'Medium',
                            'url': url,
                            'parameter': 'N/A',
                            'payload': 'Origin: null',
                            'evidence': (
                                'Server allows "null" origin. This can be exploited '
                                'via sandboxed iframes or data: URLs.'
                            ),
                            'recommendation': 'Reject "null" Origin header. Implement proper origin validation. Use specific trusted origins only. Be aware that sandboxed iframes send Origin: null.'
                        }
                        findings.append(finding)
                
                # Only report first finding per type
                if findings:
                    break
        
        except requests.exceptions.RequestException as e:
            if self.config.get('verbose'):
                print(f"Warning: Could not check CORS for {url}: {e}")
        
        return findings
