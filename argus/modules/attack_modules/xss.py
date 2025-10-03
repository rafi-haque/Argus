"""XSS (Cross-Site Scripting) attack module - Reflected and DOM-based detection."""
from typing import Dict, List
import requests
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .base import BaseAttackModule


class XSSModule(BaseAttackModule):
    """Detects XSS vulnerabilities."""
    
    def __init__(self, config: dict):
        """Initialize XSS module."""
        super().__init__(config)
        self.timeout = config.get('performance', {}).get('timeout', 10)
    
    def name(self) -> str:
        """Return module name."""
        return "xss"
    
    def description(self) -> str:
        """Return module description."""
        return "Detects Cross-Site Scripting (XSS) vulnerabilities (Reflected and DOM-based)"
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if XSS module should run on this parameter.
        
        Args:
            parameter: Parameter dict
            context: Context dict
        
        Returns:
            bool: True if parameter accepts user input
        """
        if not parameter.get('name'):
            return False
        
        # Apply to all query and body parameters (user input)
        return parameter.get('location') in ['query', 'body']
    
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Scan for XSS vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Try reflected XSS
        reflected_finding = self._test_reflected_xss(url, parameter, session)
        if reflected_finding:
            findings.append(reflected_finding)
        
        # Try DOM-based XSS (if Playwright available)
        if not reflected_finding:  # Only if reflected didn't find anything
            dom_finding = self._test_dom_xss(url, parameter)
            if dom_finding:
                findings.append(dom_finding)
        
        return findings
    
    def _test_reflected_xss(self, url: str, parameter: dict, session: requests.Session) -> Dict:
        """Test for reflected XSS.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            session: Requests session
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter['name']
        param_location = parameter['location']
        
        # Generate unique test payloads
        unique_id = hashlib.md5(f"{url}{param_name}".encode()).hexdigest()[:8]
        
        # Test payloads (ordered from safest to more complex)
        test_payloads = [
            f"<argus_xss_{unique_id}>",  # Simple tag
            f"<script>argus_xss_{unique_id}</script>",  # Script tag
            f"'><script>argus_xss_{unique_id}</script>",  # Break out of attribute
            f"\"><script>argus_xss_{unique_id}</script>",  # Break out of double-quoted attr
            f"javascript:argus_xss_{unique_id}",  # JavaScript protocol
            f"<img src=x onerror=argus_xss_{unique_id}>",  # Event handler
        ]
        
        for payload in test_payloads:
            try:
                # Inject payload
                test_url = self._inject_payload(url, param_name, payload, param_location)
                
                # Make request
                response = session.get(test_url, timeout=self.timeout)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    # Check if it's in a dangerous context (not HTML-encoded)
                    html_lower = response.text.lower()
                    
                    # Look for unencoded script tags or event handlers
                    dangerous = False
                    if '<script>' in html_lower and unique_id in response.text:
                        dangerous = True
                    elif 'onerror=' in html_lower and unique_id in response.text:
                        dangerous = True
                    elif 'javascript:' in html_lower and unique_id in response.text:
                        dangerous = True
                    
                    if dangerous or '<' in payload:  # Any tag reflection is concerning
                        evidence = (
                            f"Reflected XSS detected. Payload '{payload}' was reflected "
                            f"in the response without proper encoding."
                        )
                        
                        return {
                            'name': 'Cross-Site Scripting (XSS) - Reflected',
                            'severity': 'High',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': evidence
                        }
            
            except requests.exceptions.RequestException:
                continue
        
        return None
    
    def _test_dom_xss(self, url: str, parameter: dict) -> Dict:
        """Test for DOM-based XSS using headless browser.
        
        Args:
            url: URL to test
            parameter: Parameter to test
        
        Returns:
            dict: Finding if vulnerable, None otherwise
        """
        param_name = parameter['name']
        param_location = parameter['location']
        
        try:
            from playwright.sync_api import sync_playwright
            import hashlib
            
            # Generate unique identifier
            unique_id = hashlib.md5(f"{url}{param_name}".encode()).hexdigest()[:8]
            
            # Test payload that would trigger alert if executed
            test_payloads = [
                f"<img src=x onerror=alert('{unique_id}')>",
                f"'><script>alert('{unique_id}')</script>",
                f"\"><script>alert('{unique_id}')</script>",
            ]
            
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                # Track dialog events (alerts)
                alert_triggered = False
                alert_message = None
                
                def handle_dialog(dialog):
                    nonlocal alert_triggered, alert_message
                    alert_triggered = True
                    alert_message = dialog.message
                    dialog.accept()
                
                page.on('dialog', handle_dialog)
                
                # Test each payload
                for payload in test_payloads:
                    alert_triggered = False
                    alert_message = None
                    
                    # Inject payload
                    test_url = self._inject_payload(url, param_name, payload, param_location)
                    
                    try:
                        page.goto(test_url, timeout=self.timeout * 1000, wait_until='load')
                        page.wait_for_timeout(1000)  # Wait for JS execution
                        
                        # Check if alert was triggered with our identifier
                        if alert_triggered and unique_id in str(alert_message):
                            browser.close()
                            
                            evidence = (
                                f"DOM-based XSS detected. Payload '{payload}' triggered "
                                f"JavaScript execution with alert containing '{unique_id}'."
                            )
                            
                            return {
                                'name': 'Cross-Site Scripting (XSS) - DOM-Based',
                                'severity': 'High',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': evidence
                            }
                    
                    except Exception:
                        continue
                
                browser.close()
        
        except ImportError:
            # Playwright not available
            pass
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Warning: DOM XSS test failed: {e}")
        
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
        return url
