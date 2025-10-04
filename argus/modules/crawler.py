"""Crawler module for discovering web application attack surface."""
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs
import re
import requests
from bs4 import BeautifulSoup


class Crawler:
    """Web crawler that discovers URLs and parameters."""
    
    def __init__(self, config: dict):
        """Initialize crawler with configuration.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.visited_urls: Set[str] = set()
        self.max_depth = config.get('crawler', {}).get('max_depth', 3)
        self.timeout = config.get('performance', {}).get('timeout', 10)
        self.use_active_crawling = config.get('crawler', {}).get('active', False)
    
    def crawl(self, seed_url: str, scope_config: dict) -> List[Dict]:
        """Discover site endpoints and parameters using passive (and optionally active) crawling.
        
        Args:
            seed_url: Starting URL
            scope_config: Include/exclude pattern configuration
        
        Returns:
            list: Site map entries
        """
        # Passive crawling
        site_map = self._passive_crawl(seed_url, scope_config)
        
        # Discover common API endpoints
        api_map = self._discover_api_endpoints(seed_url, scope_config)
        site_map.extend(api_map)
        
        # Active crawling with Playwright (if enabled)
        if self.use_active_crawling:
            try:
                active_map = self._active_crawl(seed_url, scope_config)
                # Merge active findings with passive
                site_map.extend(active_map)
            except Exception as e:
                if self.config.get('verbose'):
                    print(f"Warning: Active crawling failed: {e}")
        
        # Remove duplicates
        seen_urls = set()
        unique_map = []
        for entry in site_map:
            url_key = f"{entry['url']}:{entry['method']}"
            if url_key not in seen_urls:
                seen_urls.add(url_key)
                unique_map.append(entry)
        
        return unique_map
    
    def _passive_crawl(self, seed_url: str, scope_config: dict) -> List[Dict]:
        """Discover site endpoints and parameters using passive crawling.
        
        Args:
            seed_url: Starting URL
            scope_config: Include/exclude pattern configuration
        
        Returns:
            list: Site map entries
        """
        site_map = []
        to_visit = [(seed_url, 0)]  # (url, depth)
        
        session = requests.Session()
        
        # Set authentication if configured
        if self.config.get('auth'):
            auth = self.config['auth']
            if auth['type'] == 'header':
                session.headers[auth['name']] = auth['value']
        
        while to_visit:
            current_url, depth = to_visit.pop(0)
            
            # Skip if already visited or depth exceeded
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            # Check scope
            if not self._in_scope(current_url, scope_config):
                continue
            
            self.visited_urls.add(current_url)
            
            try:
                # Fetch the page
                response = session.get(current_url, timeout=self.timeout, allow_redirects=True)
                
                # Add current URL to site map with query parameters
                entry = self._create_site_map_entry(current_url, 'GET')
                site_map.append(entry)
                
                # Parse HTML for links and forms
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'lxml')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        
                        # Remove fragment
                        absolute_url = absolute_url.split('#')[0]
                        
                        if absolute_url and absolute_url not in self.visited_urls:
                            to_visit.append((absolute_url, depth + 1))
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_entry = self._extract_form(form, current_url)
                        if form_entry:
                            site_map.append(form_entry)
            
            except requests.exceptions.RequestException as e:
                if self.config.get('verbose'):
                    print(f"Warning: Could not crawl {current_url}: {e}")
                continue
        
        return site_map
    
    def _in_scope(self, url: str, scope_config: dict) -> bool:
        """Check if URL is in scope.
        
        Args:
            url: URL to check
            scope_config: Scope configuration with include/exclude patterns
        
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
            dict: Site map entry
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
        
        # Reconstruct clean URL (without query string for the entry)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        
        return {
            'url': clean_url,
            'method': method,
            'parameters': parameters
        }
    
    def _extract_form(self, form, base_url: str) -> Dict:
        """Extract form as site map entry.
        
        Args:
            form: BeautifulSoup form element
            base_url: Base URL for resolving relative actions
        
        Returns:
            dict: Site map entry for form, or None if invalid
        """
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Resolve relative action
        form_url = urljoin(base_url, action) if action else base_url
        
        # Extract form inputs
        parameters = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name')
            if not input_name:
                continue
            
            input_value = input_tag.get('value', '')
            input_type = input_tag.get('type', 'text')
            
            # Skip submit buttons
            if input_type in ['submit', 'button', 'image']:
                continue
            
            parameters.append({
                'name': input_name,
                'value': input_value,
                'location': 'body' if method == 'POST' else 'query'
            })
        
        if not parameters:
            return None
        
        return {
            'url': form_url,
            'method': method,
            'parameters': parameters
        }
    
    def _discover_api_endpoints(self, seed_url: str, scope_config: dict) -> List[Dict]:
        """Discover common API endpoints by probing known patterns.
        
        Args:
            seed_url: Base URL
            scope_config: Scope configuration
        
        Returns:
            list: Discovered API endpoint entries
        """
        api_map = []
        parsed = urlparse(seed_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        session = requests.Session()
        if self.config.get('auth'):
            auth = self.config['auth']
            if auth['type'] == 'header':
                session.headers[auth['name']] = auth['value']
        
        # Common API path patterns
        api_patterns = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/rest',
            '/rest/v1',
            '/rest/api',
            '/rest/user',
            '/rest/products',
            '/rest/products/search',  # Juice Shop specific
            '/graphql',
            '/v1',
            '/v2',
        ]
        
        # Common resource endpoints (RESTful patterns)
        resource_patterns = [
            'users', 'user', 'products', 'product', 'items', 'item',
            'orders', 'order', 'accounts', 'account', 'auth', 'login',
            'register', 'profile', 'search', 'comments', 'posts',
            'reviews', 'basket', 'cart', 'checkout', 'payment'
        ]
        
        discovered_endpoints = []
        
        # Try API base paths
        for api_path in api_patterns:
            test_url = f"{base_url}{api_path}"
            if not self._in_scope(test_url, scope_config):
                continue
            
            try:
                response = session.get(test_url, timeout=self.timeout, allow_redirects=True)
                if response.status_code != 404:
                    discovered_endpoints.append(test_url)
                    
                    # Only try resources for base API paths, not nested ones
                    # This prevents explosion of /api/v1/products/users/items/etc.
                    if api_path in ['/api', '/api/v1', '/api/v2', '/rest', '/rest/v1', '/rest/api']:
                        # Try common resources under this API path
                        for resource in resource_patterns:
                            resource_url = f"{test_url}/{resource}"
                            if resource_url not in self.visited_urls:
                                try:
                                    res_response = session.get(resource_url, timeout=self.timeout, allow_redirects=True)
                                    if res_response.status_code != 404:
                                        discovered_endpoints.append(resource_url)
                                except requests.exceptions.RequestException:
                                    pass
            except requests.exceptions.RequestException:
                pass
        
        # Create site map entries for discovered endpoints
        for url in discovered_endpoints:
            if url not in self.visited_urls:
                self.visited_urls.add(url)
                entry = self._create_site_map_entry(url, 'GET')
                api_map.append(entry)
                
                # For search-like endpoints, add common query parameters
                # Only add params if the endpoint name suggests it accepts them
                url_lower = url.lower()
                if any(term in url_lower for term in ['search', 'find', 'query', 'filter']):
                    # Search/filter endpoints - test with search params
                    test_params = [
                        ('q', 'test'),
                        ('search', 'test'),
                        ('query', 'test'),
                        ('keyword', 'test')
                    ]
                    
                    for param_name, param_value in test_params:
                        param_url = f"{url}?{param_name}={param_value}"
                        param_entry = {
                            'url': param_url,
                            'method': 'GET',
                            'parameters': [{
                                'name': param_name,
                                'value': param_value,
                                'location': 'query'
                            }]
                        }
                        api_map.append(param_entry)
                
                elif any(term in url_lower for term in ['user', 'product', 'item', 'order', 'account']):
                    # Resource endpoints - test with ID param
                    param_url = f"{url}?id=1"
                    param_entry = {
                        'url': param_url,
                        'method': 'GET',
                        'parameters': [{
                            'name': 'id',
                            'value': '1',
                            'location': 'query'
                        }]
                    }
                    api_map.append(param_entry)
                
                if self.config.get('verbose'):
                    print(f"   Discovered API endpoint: {url}")
        
        return api_map
    
    def _active_crawl(self, seed_url: str, scope_config: dict) -> List[Dict]:
        """Discover endpoints using headless browser (Playwright).
        
        Args:
            seed_url: Starting URL
            scope_config: Scope configuration
        
        Returns:
            list: Site map entries discovered via JavaScript
        """
        site_map = []
        
        try:
            from playwright.sync_api import sync_playwright
            
            with sync_playwright() as p:
                # Launch browser
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                
                # Track network requests
                discovered_urls = set()
                
                def handle_request(request):
                    url = request.url
                    if self._in_scope(url, scope_config):
                        discovered_urls.add(url)
                
                page.on('request', handle_request)
                
                # Navigate to seed URL
                page.goto(seed_url, timeout=self.timeout * 1000, wait_until='networkidle')
                
                # Extract links from rendered DOM
                links = page.eval_on_selector_all('a[href]', 
                    'elements => elements.map(e => e.href)')
                
                for link in links:
                    if link and self._in_scope(link, scope_config):
                        discovered_urls.add(link)
                
                # Create site map entries
                for url in discovered_urls:
                    if url not in self.visited_urls:
                        entry = self._create_site_map_entry(url, 'GET')
                        site_map.append(entry)
                        self.visited_urls.add(url)
                
                browser.close()
        
        except ImportError:
            if self.config.get('verbose'):
                print("Warning: Playwright not available for active crawling")
        except Exception as e:
            if self.config.get('verbose'):
                print(f"Warning: Active crawling error: {e}")
        
        return site_map
