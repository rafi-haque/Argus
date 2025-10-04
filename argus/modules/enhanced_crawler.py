"""Enhanced crawler with modern web support.

Features:
- Playwright-based browser automation
- JavaScript execution and rendering
- XHR/Fetch request interception
- WebSocket connection detection
- SPA (Single Page Application) support
- Form filling with state tracking
- API endpoint extraction from JS bundles
- Async/await throughout
"""
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
import re
import asyncio
import json
from pathlib import Path
from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Route
from bs4 import BeautifulSoup
import httpx


class JavaScriptAnalyzer:
    """Analyzes JavaScript code to extract API endpoints and parameters."""
    
    # Common API endpoint patterns
    API_PATTERNS = [
        r'["\']/(api|rest|v\d+|graphql)/[^"\']+["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'\$\.(get|post|put|delete|ajax)\(["\']([^"\']+)["\']',
        r'XMLHttpRequest.*open\(["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'path\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    # Parameter patterns
    PARAM_PATTERNS = [
        r'params?\s*[:=]\s*\{([^}]+)\}',
        r'data\s*[:=]\s*\{([^}]+)\}',
        r'query\s*[:=]\s*\{([^}]+)\}',
        r'(\w+)\s*[:=]\s*["\']',
    ]
    
    def __init__(self):
        self.discovered_endpoints: Set[str] = set()
        self.discovered_params: Dict[str, Set[str]] = {}
    
    def analyze_script(self, script_content: str, base_url: str) -> List[Dict]:
        """Analyze JavaScript code for endpoints and parameters.
        
        Args:
            script_content: JavaScript source code
            base_url: Base URL for resolving relative paths
        
        Returns:
            List of discovered endpoints with parameters
        """
        findings = []
        
        # Extract API endpoints
        for pattern in self.API_PATTERNS:
            matches = re.finditer(pattern, script_content, re.IGNORECASE)
            for match in matches:
                # Get the URL from the match (last group usually)
                url = match.groups()[-1] if match.groups() else match.group(0).strip('"\'')
                
                # Skip if not a valid path
                if not url or url.startswith('http://') or url.startswith('https://'):
                    if url:
                        self.discovered_endpoints.add(url)
                    continue
                
                # Resolve relative URL
                absolute_url = urljoin(base_url, url)
                self.discovered_endpoints.add(absolute_url)
        
        # Extract parameters from objects
        for pattern in self.PARAM_PATTERNS:
            matches = re.finditer(pattern, script_content, re.MULTILINE)
            for match in matches:
                param_block = match.group(0)
                # Extract parameter names
                param_names = re.findall(r'(\w+)\s*:', param_block)
                for param_name in param_names:
                    if param_name not in ['function', 'var', 'let', 'const', 'if', 'else', 'for', 'while']:
                        if base_url not in self.discovered_params:
                            self.discovered_params[base_url] = set()
                        self.discovered_params[base_url].add(param_name)
        
        # Build findings
        for endpoint in self.discovered_endpoints:
            params = []
            if endpoint in self.discovered_params:
                params = [
                    {'name': p, 'value': '', 'location': 'query'}
                    for p in self.discovered_params[endpoint]
                ]
            
            findings.append({
                'url': endpoint,
                'method': 'GET',
                'parameters': params,
                'source': 'javascript_analysis'
            })
        
        return findings


class NetworkInterceptor:
    """Intercepts and captures network requests made by the browser."""
    
    def __init__(self):
        self.captured_requests: List[Dict] = []
        self.websocket_urls: Set[str] = set()
        self.api_calls: List[Dict] = []
    
    async def handle_request(self, route: Route):
        """Handle intercepted request.
        
        Args:
            route: Playwright route object
        """
        request = route.request
        
        # Capture request details
        request_info = {
            'url': request.url,
            'method': request.method,
            'headers': dict(request.headers),
            'post_data': request.post_data if request.post_data else None,
            'resource_type': request.resource_type
        }
        
        # Detect WebSocket connections
        if request.resource_type == 'websocket':
            self.websocket_urls.add(request.url)
        
        # Detect API calls (XHR/Fetch)
        if request.resource_type in ['xhr', 'fetch']:
            self.api_calls.append(request_info)
            
            # Extract parameters from POST data
            if request.post_data:
                try:
                    # Try to parse as JSON
                    data = json.loads(request.post_data)
                    request_info['parsed_data'] = data
                except:
                    # Try to parse as form data
                    if '=' in request.post_data:
                        request_info['parsed_data'] = dict(
                            pair.split('=', 1) for pair in request.post_data.split('&') if '=' in pair
                        )
        
        self.captured_requests.append(request_info)
        
        # Continue the request
        await route.continue_()
    
    def get_api_endpoints(self) -> List[Dict]:
        """Extract API endpoints from captured requests.
        
        Returns:
            List of API endpoint entries
        """
        endpoints = []
        seen_urls = set()
        
        for api_call in self.api_calls:
            url = api_call['url']
            
            # Skip duplicates
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            # Parse URL for query parameters
            parsed = urlparse(url)
            parameters = []
            
            if parsed.query:
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                for name, values in query_params.items():
                    parameters.append({
                        'name': name,
                        'value': values[0] if values else '',
                        'location': 'query'
                    })
            
            # Add POST data parameters
            if api_call['method'] in ['POST', 'PUT', 'PATCH'] and 'parsed_data' in api_call:
                data = api_call['parsed_data']
                if isinstance(data, dict):
                    for name, value in data.items():
                        parameters.append({
                            'name': name,
                            'value': str(value) if value else '',
                            'location': 'body'
                        })
            
            endpoints.append({
                'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                'method': api_call['method'],
                'parameters': parameters,
                'source': 'network_interception',
                'resource_type': api_call['resource_type']
            })
        
        return endpoints


class FormHandler:
    """Handles form filling and submission."""
    
    def __init__(self, config: dict):
        self.config = config
        self.filled_forms: List[Dict] = []
    
    async def fill_and_submit_forms(self, page: Page, base_url: str) -> List[Dict]:
        """Find, fill, and analyze forms on the page.
        
        Args:
            page: Playwright page object
            base_url: Base URL for the page
        
        Returns:
            List of form entries with parameters
        """
        forms = []
        
        # Get all forms
        form_elements = await page.query_selector_all('form')
        
        for i, form in enumerate(form_elements):
            try:
                # Extract form details
                action = await form.get_attribute('action') or ''
                method = (await form.get_attribute('method') or 'GET').upper()
                
                # Resolve action URL
                form_url = urljoin(base_url, action) if action else base_url
                
                # Find inputs
                inputs = await form.query_selector_all('input, textarea, select')
                parameters = []
                
                for input_elem in inputs:
                    input_name = await input_elem.get_attribute('name')
                    input_type = await input_elem.get_attribute('type') or 'text'
                    
                    if not input_name:
                        continue
                    
                    # Determine location
                    location = 'body' if method in ['POST', 'PUT', 'PATCH'] else 'query'
                    
                    # Get current value
                    value = await input_elem.get_attribute('value') or ''
                    
                    parameters.append({
                        'name': input_name,
                        'value': value,
                        'location': location,
                        'type': input_type
                    })
                    
                    # Auto-fill based on input type (optional)
                    if self.config.get('crawler', {}).get('auto_fill_forms', False):
                        await self._fill_input(input_elem, input_type, input_name)
                
                forms.append({
                    'url': form_url,
                    'method': method,
                    'parameters': parameters,
                    'source': 'form_analysis'
                })
                
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"Warning: Could not analyze form {i}: {e}")
                continue
        
        return forms
    
    async def _fill_input(self, input_elem, input_type: str, input_name: str):
        """Fill an input element with appropriate test data.
        
        Args:
            input_elem: Playwright element
            input_type: Input type attribute
            input_name: Input name attribute
        """
        # Skip hidden and submit inputs
        if input_type in ['hidden', 'submit', 'button']:
            return
        
        # Determine test value based on name/type
        test_value = ''
        
        if 'email' in input_name.lower() or input_type == 'email':
            test_value = 'test@example.com'
        elif 'password' in input_name.lower() or input_type == 'password':
            test_value = 'TestPass123!'
        elif 'phone' in input_name.lower() or input_type == 'tel':
            test_value = '555-0100'
        elif 'url' in input_name.lower() or input_type == 'url':
            test_value = 'https://example.com'
        elif input_type == 'number':
            test_value = '42'
        elif input_type == 'date':
            test_value = '2024-01-01'
        elif input_type == 'checkbox':
            try:
                await input_elem.check()
            except:
                pass
            return
        else:
            test_value = f'test_{input_name}'
        
        # Fill the input
        try:
            await input_elem.fill(test_value)
        except Exception:
            pass  # Some inputs might not be fillable


class EnhancedCrawler:
    """Enhanced crawler with modern web support using Playwright."""
    
    def __init__(self, config: dict):
        """Initialize enhanced crawler.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.visited_urls: Set[str] = set()
        self.max_depth = config.get('crawler', {}).get('max_depth', 3)
        self.timeout = config.get('performance', {}).get('timeout', 10) * 1000  # Convert to ms
        self.headless = config.get('crawler', {}).get('headless', True)
        self.wait_for_network = config.get('crawler', {}).get('wait_for_network', True)
        
        # Components
        self.js_analyzer = JavaScriptAnalyzer()
        self.network_interceptor = NetworkInterceptor()
        self.form_handler = FormHandler(config)
        
        # Storage
        self.site_map: List[Dict] = []
        self.websocket_urls: Set[str] = set()
    
    async def crawl(self, seed_url: str, scope_config: dict) -> List[Dict]:
        """Crawl site with modern web support.
        
        Args:
            seed_url: Starting URL
            scope_config: Scope configuration
        
        Returns:
            List of site map entries
        """
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            # Set authentication if configured
            if self.config.get('auth'):
                auth = self.config['auth']
                if auth['type'] == 'header':
                    await context.set_extra_http_headers({auth['name']: auth['value']})
            
            # Enable network interception
            await context.route('**/*', self.network_interceptor.handle_request)
            
            # Create page
            page = await context.new_page()
            
            # Crawl
            await self._crawl_recursive(page, seed_url, scope_config, 0)
            
            # Get WebSocket URLs
            self.websocket_urls = self.network_interceptor.websocket_urls
            
            # Add captured API endpoints
            api_endpoints = self.network_interceptor.get_api_endpoints()
            self.site_map.extend(api_endpoints)
            
            # Close browser
            await browser.close()
        
        # Deduplicate
        seen = set()
        unique_map = []
        for entry in self.site_map:
            key = (entry['url'], entry['method'])
            if key not in seen:
                seen.add(key)
                unique_map.append(entry)
        
        return unique_map
    
    async def _crawl_recursive(
        self,
        page: Page,
        url: str,
        scope_config: dict,
        depth: int
    ):
        """Recursively crawl pages.
        
        Args:
            page: Playwright page
            url: URL to crawl
            scope_config: Scope configuration
            depth: Current crawl depth
        """
        # Check depth and visited
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        # Check scope
        if not self._in_scope(url, scope_config):
            return
        
        self.visited_urls.add(url)
        
        if self.config.get('verbose'):
            print(f"  Crawling: {url} (depth {depth})")
        
        try:
            # Navigate to page
            response = await page.goto(url, timeout=self.timeout, wait_until='networkidle' if self.wait_for_network else 'domcontentloaded')
            
            if not response or response.status >= 400:
                return
            
            # Wait for JavaScript execution
            await page.wait_for_timeout(1000)  # 1 second for JS to run
            
            # Extract page URL and parameters from current location
            current_url = page.url
            entry = self._create_site_map_entry(current_url, 'GET')
            self.site_map.append(entry)
            
            # Analyze forms
            forms = await self.form_handler.fill_and_submit_forms(page, current_url)
            self.site_map.extend(forms)
            
            # Extract links for further crawling
            links = await page.query_selector_all('a[href]')
            next_urls = []
            
            for link in links[:50]:  # Limit to 50 links per page
                try:
                    href = await link.get_attribute('href')
                    if href:
                        absolute_url = urljoin(current_url, href)
                        absolute_url = absolute_url.split('#')[0]  # Remove fragment
                        
                        if absolute_url and absolute_url not in self.visited_urls:
                            next_urls.append(absolute_url)
                except:
                    continue
            
            # Analyze JavaScript
            scripts = await page.query_selector_all('script')
            for script in scripts:
                try:
                    script_content = await script.inner_text()
                    if script_content:
                        js_findings = self.js_analyzer.analyze_script(script_content, current_url)
                        self.site_map.extend(js_findings)
                except:
                    continue
            
            # Also get external script sources
            script_srcs = await page.query_selector_all('script[src]')
            for script_elem in script_srcs:
                try:
                    src = await script_elem.get_attribute('src')
                    if src:
                        script_url = urljoin(current_url, src)
                        # Fetch and analyze external script
                        async with httpx.AsyncClient() as client:
                            try:
                                resp = await client.get(script_url, timeout=5)
                                if resp.status_code == 200:
                                    js_findings = self.js_analyzer.analyze_script(resp.text, current_url)
                                    self.site_map.extend(js_findings)
                            except:
                                pass
                except:
                    continue
            
            # Crawl discovered links
            for next_url in next_urls[:10]:  # Limit to 10 per page to avoid explosion
                await self._crawl_recursive(page, next_url, scope_config, depth + 1)
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"  Warning: Could not crawl {url}: {e}")
    
    def _in_scope(self, url: str, scope_config: dict) -> bool:
        """Check if URL is in scope.
        
        Args:
            url: URL to check
            scope_config: Scope configuration
        
        Returns:
            bool: True if in scope
        """
        include_patterns = scope_config.get('include_patterns', [])
        exclude_patterns = scope_config.get('exclude_patterns', [])
        
        # Check exclude patterns first
        for pattern in exclude_patterns:
            if re.search(pattern, url):
                return False
        
        # If include patterns specified, URL must match at least one
        if include_patterns:
            return any(re.search(pattern, url) for pattern in include_patterns)
        
        return True
    
    def _create_site_map_entry(self, url: str, method: str = 'GET') -> Dict:
        """Create site map entry from URL.
        
        Args:
            url: URL to process
            method: HTTP method
        
        Returns:
            Site map entry dict
        """
        parsed = urlparse(url)
        parameters = []
        
        # Extract query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                for value in values:
                    parameters.append({
                        'name': name,
                        'value': value or '',
                        'location': 'query'
                    })
        
        # Reconstruct URL
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        
        return {
            'url': clean_url,
            'method': method,
            'parameters': parameters,
            'source': 'html_crawl'
        }
    
    def get_websocket_urls(self) -> Set[str]:
        """Get discovered WebSocket URLs.
        
        Returns:
            Set of WebSocket URLs
        """
        return self.websocket_urls


# Backward compatibility: create alias for standard crawler interface
class Crawler(EnhancedCrawler):
    """Alias for EnhancedCrawler to maintain backward compatibility."""
    pass
