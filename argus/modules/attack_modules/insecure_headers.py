"""Insecure Headers Attack Module - Detects missing security headers."""
from typing import Dict, List
import httpx
from .async_base import AsyncBaseAttackModule


class InsecureHeadersModule(AsyncBaseAttackModule):
    """Detects missing or misconfigured security headers."""
    
    # Security headers to check
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'Medium',
            'description': 'Helps prevent XSS and data injection attacks'
        },
        'Strict-Transport-Security': {
            'severity': 'High',
            'description': 'Enforces HTTPS connections'
        },
        'X-Frame-Options': {
            'severity': 'Medium',
            'description': 'Prevents clickjacking attacks'
        },
        'X-Content-Type-Options': {
            'severity': 'Low',
            'description': 'Prevents MIME-sniffing attacks'
        },
        'X-XSS-Protection': {
            'severity': 'Low',
            'description': 'Enables browser XSS filtering'
        },
        'Referrer-Policy': {
            'severity': 'Low',
            'description': 'Controls referrer information'
        },
        'Permissions-Policy': {
            'severity': 'Info',
            'description': 'Controls browser features and APIs'
        }
    }
    
    def name(self) -> str:
        """Return module name."""
        return "insecure_headers"
    
    def description(self) -> str:
        """Return module description."""
        return "Checks for missing or misconfigured security headers"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Always applicable - checks headers at URL level.
        
        Args:
            parameter: Parameter dict (ignored for this module)
            context: Context dict with URL
        
        Returns:
            bool: Always True
        """
        return True
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Scan for missing security headers.
        
        Args:
            url: URL to check
            parameter: Parameter dict (ignored)
            session: Requests session
        
        Returns:
            list: Findings for missing headers
        """
        findings = []
        
        try:
            # Make GET request
            response = await client.get(
                url,
                timeout=self.config.get('performance', {}).get('timeout', 10),
                follow_redirects=True
            )
            
            # Check each security header
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name not in response.headers:
                    finding = {
                        'name': f'Missing Security Header: {header_name}',
                        'severity': header_info['severity'],
                        'url': url,
                        'parameter': 'N/A',
                        'payload': 'N/A',
                        'evidence': f'Header "{header_name}" is missing. {header_info["description"]}.',
                        'recommendation': f'Add {header_name} header with appropriate value. See OWASP Secure Headers Project for recommended configurations. {header_info["description"]}'
                    }
                    findings.append(finding)
            
            # Check for insecure headers
            if 'Server' in response.headers:
                server_value = response.headers['Server']
                # If server header reveals detailed version info, it's a finding
                if any(char.isdigit() for char in server_value):
                    finding = {
                        'name': 'Information Disclosure: Server Header',
                        'severity': 'Info',
                        'url': url,
                        'parameter': 'N/A',
                        'payload': 'N/A',
                        'evidence': f'Server header reveals version information: "{server_value}"',
                        'recommendation': 'Remove or obfuscate Server header to prevent version disclosure. Configure web server to suppress detailed version information. Use generic values or remove header entirely.'
                    }
                    findings.append(finding)
            
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                finding = {
                    'name': 'Information Disclosure: X-Powered-By Header',
                    'severity': 'Info',
                    'url': url,
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'evidence': f'X-Powered-By header reveals technology: "{powered_by}"',
                    'recommendation': 'Remove X-Powered-By header to prevent technology disclosure. Configure application framework to suppress this header. This reduces attack surface by hiding implementation details.'
                }
                findings.append(finding)
        
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            # Don't fail on network errors, just skip
            if self.config.get('verbose'):
                print(f"Warning: Could not check headers for {url}: {e}")
        
        return findings
