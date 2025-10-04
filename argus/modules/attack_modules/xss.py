"""XSS (Cross-Site Scripting) attack module - Reflected and DOM-based detection."""
from typing import Dict, List
import httpx
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .async_base import AsyncBaseAttackModule


class XSSModule(AsyncBaseAttackModule):
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
        return "Detects Cross-Site Scripting (XSS) vulnerabilities with browser validation"
    
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
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Scan for XSS vulnerabilities.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: Async HTTP client
        
        Returns:
            list: Findings
        """
        findings = []
        
        # Try reflected XSS with browser validation
        reflected_finding = await self._test_reflected_xss_with_browser(url, parameter, client)
        if reflected_finding:
            findings.append(reflected_finding)
            return findings  # Found confirmed XSS
        
        # Fallback to simple reflection detection
        reflected_finding = await self._test_reflected_xss(url, parameter, client)
        if reflected_finding:
            findings.append(reflected_finding)
        
        # Try DOM-based XSS (if Playwright available)
        if not reflected_finding:  # Only if reflected didn't find anything
            dom_finding = await self._test_dom_xss(url, parameter)
            if dom_finding:
                findings.append(dom_finding)
        
        return findings
    
    async def _test_reflected_xss_with_browser(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
        """Test for reflected XSS with headless browser validation.
        
        This method confirms that the XSS payload actually executes JavaScript
        in a real browser, dramatically reducing false positives.
        
        Args:
            url: URL to test
            parameter: Parameter to test
            client: Async HTTP client
        
        Returns:
            dict: Finding if vulnerable and confirmed, None otherwise
        """
        # Only attempt browser validation if Playwright is available
        if not self.config.get('use_browser_validation', True):
            return None
        
        try:
            from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
            import hashlib
            
            param_name = parameter['name']
            param_location = parameter['location']
            
            # Generate unique identifier
            unique_id = hashlib.md5(f"{url}{param_name}".encode()).hexdigest()[:8]
            
            # Test payloads that would trigger observable behavior
            test_payloads = [
                f"<script>window.argus_{unique_id}=1</script>",
                f"'><script>window.argus_{unique_id}=1</script>",
                f"\"><script>window.argus_{unique_id}=1</script>",
                f"<img src=x onerror=window.argus_{unique_id}=1>",
            ]
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                for payload in test_payloads[:3]:  # Test first 3
                    try:
                        # Inject payload
                        test_url = self._inject_payload(url, param_name, payload, param_location)
                        
                        # Navigate and wait for page load
                        await page.goto(test_url, wait_until='networkidle', timeout=10000)
                        
                        # Check if our JavaScript executed
                        result = await page.evaluate(f"typeof window.argus_{unique_id}")
                        
                        if result == 'number':  # Our script executed!
                            await browser.close()
                            return {
                                'name': 'Cross-Site Scripting (XSS) - Confirmed',
                                'severity': 'Critical',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': 'XSS payload confirmed to execute JavaScript in browser. Custom window property was set successfully.',
                                'recommendation': 'Implement proper output encoding: Use context-aware escaping (HTML, JavaScript, URL, CSS). Apply Content Security Policy (CSP) headers. Validate and sanitize all user input. Use security libraries like DOMPurify for rich content.'
                            }
                    
                    except PlaywrightTimeout:
                        continue
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"Browser validation error: {e}")
                        continue
                
                await browser.close()
        
        except ImportError:
            # Playwright not available, skip browser validation
            if self.config.get('verbose'):
                print("Playwright not available for browser validation")
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Browser validation error: {e}")
        
        return None
    
    async def _test_reflected_xss(self, url: str, parameter: dict, client: httpx.AsyncClient) -> Dict:
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
                response = await client.get(test_url, timeout=self.timeout)
                
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
                            'evidence': evidence,
                            'recommendation': 'Encode output based on context: HTML entity encoding for HTML context, JavaScript encoding for JS context, URL encoding for URLs. Implement Content Security Policy (CSP). Use template engines with auto-escaping. Validate input on server side.'
                        }
            
            except (httpx.HTTPError, httpx.TimeoutException):
                continue
        
        return None
    
    async def _test_dom_xss(self, url: str, parameter: dict) -> Dict:
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
            from playwright.async_api import async_playwright
            import hashlib
            
            # Generate unique identifier
            unique_id = hashlib.md5(f"{url}{param_name}".encode()).hexdigest()[:8]
            
            # Test payload that would trigger alert if executed
            test_payloads = [
                f"<img src=x onerror=alert('{unique_id}')>",
                f"'><script>alert('{unique_id}')</script>",
                f"\"><script>alert('{unique_id}')</script>",
            ]
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                
                # Track dialog events (alerts)
                alert_triggered = False
                alert_message = None
                
                def handle_dialog(dialog):
                    nonlocal alert_triggered, alert_message
                    alert_triggered = True
                    alert_message = dialog.message
                    # Need to await this in an async context
                    import asyncio
                    asyncio.create_task(dialog.accept())
                
                page.on('dialog', handle_dialog)
                
                # Test each payload
                for payload in test_payloads:
                    alert_triggered = False
                    alert_message = None
                    
                    # Inject payload
                    test_url = self._inject_payload(url, param_name, payload, param_location)
                    
                    try:
                        await page.goto(test_url, timeout=self.timeout * 1000, wait_until='load')
                        await page.wait_for_timeout(1000)  # Wait for JS execution
                        
                        # Check if alert was triggered with our identifier
                        if alert_triggered and unique_id in str(alert_message):
                            await browser.close()
                            
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
                
                await browser.close()
        
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
