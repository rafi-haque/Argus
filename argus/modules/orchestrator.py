"""Scanning orchestrator - manages the overall scan workflow.

ASYNC-ONLY ARCHITECTURE
Uses asyncio + httpx for high-performance concurrent scanning.
"""
from typing import Dict, List
import time
import asyncio
from pathlib import Path
from argus.modules.async_http import AsyncHTTPClient
from argus.modules.rule_engine import RuleEngine


class ScannerOrchestrator:
    """Manages scanning workflow and coordinates attack modules."""
    
    def __init__(self, config: dict, modules: List):
        """Initialize orchestrator.
        
        Args:
            config: Scanner configuration
            modules: List of attack module instances
        """
        self.config = config
        self.modules = modules
        
        # Thread-safe tracking for smart optimizations
        self._header_checked_domains = set()
        self._domain_lock = asyncio.Lock()
        
        # Initialize rule engine
        rules_path = config.get('rules_file')
        if rules_path:
            self.rule_engine = RuleEngine(rules_path)
        else:
            # Try to load from default location
            default_rules = Path(__file__).parent.parent / 'config' / 'rules.yaml'
            if default_rules.exists():
                self.rule_engine = RuleEngine(str(default_rules))
            else:
                # Fall back to built-in rules
                self.rule_engine = RuleEngine()
        
        if config.get('verbose'):
            rule_count = len(self.rule_engine.list_rules(enabled_only=True))
            print(f"📋 Loaded {rule_count} prioritization rules")
    
    async def run_scan(self, seed_url: str) -> Dict:
        """Execute full scanning workflow.
        
        Args:
            seed_url: Starting URL for scan
        
        Returns:
            dict: {'site_map': list, 'findings': list, 'stats': dict}
        """
        start_time = time.time()
        
        # Initialize crawler
        from argus.modules.crawler import Crawler
        crawler = Crawler(self.config)
        
        print("🕷️  Crawling site...")
        site_map = crawler.crawl(seed_url, self.config.get('scope', {}))
        print(f"   Found {len(site_map)} endpoints\n")
        
        # Scan discovered endpoints with parallel processing
        print("🔍 Scanning for vulnerabilities...")
        
        # Use async HTTP client
        async with AsyncHTTPClient(self.config) as http_client:
            # Set authentication headers if configured
            if self.config.get('auth'):
                auth = self.config['auth']
                if auth['type'] == 'header':
                    http_client.client.headers[auth['name']] = auth['value']
            
            # Create stats tracking wrapper
            tracking_client = self._create_tracking_client(http_client)
            
            # Get concurrency settings
            max_concurrent = self.config.get('max_concurrent_scans', 10)
            module_timeout = self.config.get('module_timeout', 30)  # seconds per module
            
            # Create scan tasks for all endpoints
            scan_tasks = []
            for entry in site_map:
                task = self._scan_endpoint(entry, tracking_client, module_timeout)
                scan_tasks.append(task)
            
            # Run scans with concurrency limit
            if self.config.get('verbose'):
                print(f"   Running with max {max_concurrent} concurrent scans")
            
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def bounded_scan(task):
                async with semaphore:
                    return await task
            
            # Execute all scans with progress tracking
            results = await asyncio.gather(*[bounded_scan(task) for task in scan_tasks], return_exceptions=True)
            
            # Aggregate results
            findings = []
            urls_scanned = set()
            parameters_tested = 0
            modules_run = 0
            errors = 0
            
            for result in results:
                if isinstance(result, Exception):
                    errors += 1
                    if self.config.get('verbose'):
                        print(f"   Scan error: {result}")
                elif result:
                    findings.extend(result['findings'])
                    urls_scanned.add(result['url'])
                    parameters_tested += result['parameters_tested']
                    modules_run += result['modules_run']
                    errors += result['errors']
            
            # Get HTTP stats
            http_stats = http_client.get_stats()
        
        # Calculate stats
        scan_duration = time.time() - start_time
        
        stats = {
            'urls_scanned': len(urls_scanned),
            'parameters_tested': parameters_tested,
            'modules_run': modules_run,
            'scan_duration': scan_duration,
            'errors': errors,
            'http_requests': http_stats.get('requests', 0),
            'http_errors': http_stats.get('errors', 0),
            'avg_request_time': http_stats.get('avg_request_time', 0),
        }
        
        return {
            'site_map': site_map,
            'findings': findings,
            'stats': stats
        }
    
    async def _scan_endpoint(self, entry: Dict, tracking_client, module_timeout: int) -> Dict:
        """Scan a single endpoint with all applicable modules.
        
        Args:
            entry: Site map entry with url, method, parameters
            tracking_client: HTTP client wrapper
            module_timeout: Timeout per module in seconds
            
        Returns:
            dict: {'url': str, 'findings': list, 'parameters_tested': int, 'modules_run': int, 'errors': int}
        """
        url = entry['url']
        findings = []
        parameters_tested = 0
        modules_run = 0
        errors = 0
        
        # Smart optimization: track which header checks we've already done
        # Only need to check headers once per base domain, not per endpoint
        should_skip_headers = await self._should_skip_header_checks(url)
        
        try:
            # For each parameter in the entry
            if entry['parameters']:
                for parameter in entry['parameters']:
                    parameters_tested += 1
                    
                    # Build context
                    context = {
                        'url': url,
                        'method': entry['method'],
                        'all_params': entry['parameters']
                    }
                    
                    # Apply contextual rules to prioritize modules
                    prioritized_modules = self._get_prioritized_modules(parameter, context)
                    
                    if self.config.get('verbose'):
                        print(f"\n[ORCHESTRATOR] Testing parameter '{parameter['name']}' on {url}")
                        print(f"[ORCHESTRATOR] Prioritized modules: {[m.name() for m in prioritized_modules]}")
                    
                    # Check which modules apply to this parameter
                    for module in prioritized_modules:
                        # Skip header modules if already checked
                        if should_skip_headers and module.name() in ['insecure_headers', 'security_misconfiguration', 'headers']:
                            continue
                        
                        if self.config.get('verbose'):
                            print(f"[ORCHESTRATOR] Checking {module.name()}...")
                        
                        if module.check_applicable(parameter, context):
                            if self.config.get('verbose'):
                                print(f"[ORCHESTRATOR] {module.name()} is applicable, calling scan()...")
                            
                            modules_run += 1
                            
                            try:
                                # Run module with timeout
                                module_findings = await asyncio.wait_for(
                                    module.scan(url, parameter, tracking_client),
                                    timeout=module_timeout
                                )
                                
                                if self.config.get('verbose'):
                                    print(f"[ORCHESTRATOR] {module.name()} returned {len(module_findings)} findings")
                                
                                findings.extend(module_findings)
                            
                            except asyncio.TimeoutError:
                                errors += 1
                                if self.config.get('verbose'):
                                    print(f"[ORCHESTRATOR] Timeout in {module.name()} on {url} (>{module_timeout}s)")
                            
                            except Exception as e:
                                errors += 1
                                if self.config.get('verbose'):
                                    print(f"[ORCHESTRATOR] Error in {module.name()} on {url}: {e}")
                                    import traceback
                                    traceback.print_exc()
                        else:
                            if self.config.get('verbose'):
                                print(f"[ORCHESTRATOR] {module.name()} not applicable")
            else:
                # No parameters, just run URL-level modules (like headers)
                parameter = {'name': None, 'value': None, 'location': 'url'}
                context = {
                    'url': url,
                    'method': entry['method'],
                    'all_params': []
                }
                
                # Apply contextual rules for URL-level checks
                prioritized_modules = self._get_prioritized_modules(parameter, context)
                
                if self.config.get('verbose'):
                    print(f"\n[ORCHESTRATOR] Testing URL-level checks on {url}")
                    print(f"[ORCHESTRATOR] Prioritized modules: {[m.name() for m in prioritized_modules]}")
                
                for module in prioritized_modules:
                    # Skip header modules if already checked
                    if should_skip_headers and module.name() in ['insecure_headers', 'security_misconfiguration', 'headers']:
                        continue
                    
                    if self.config.get('verbose'):
                        print(f"[ORCHESTRATOR] Checking {module.name()}...")
                    
                    if module.check_applicable(parameter, context):
                        if self.config.get('verbose'):
                            print(f"[ORCHESTRATOR] {module.name()} is applicable, calling scan()...")
                        
                        modules_run += 1
                        
                        try:
                            # Run module with timeout
                            module_findings = await asyncio.wait_for(
                                module.scan(url, parameter, tracking_client),
                                timeout=module_timeout
                            )
                            
                            if self.config.get('verbose'):
                                print(f"[ORCHESTRATOR] {module.name()} returned {len(module_findings)} findings")
                            
                            findings.extend(module_findings)
                        
                        except asyncio.TimeoutError:
                            errors += 1
                            if self.config.get('verbose'):
                                print(f"[ORCHESTRATOR] Timeout in {module.name()} on {url} (>{module_timeout}s)")
                        
                        except Exception as e:
                            errors += 1
                            if self.config.get('verbose'):
                                print(f"[ORCHESTRATOR] Error in {module.name()} on {url}: {e}")
                                import traceback
                                traceback.print_exc()
                    else:
                        if self.config.get('verbose'):
                            print(f"[ORCHESTRATOR] {module.name()} not applicable")
        
        except Exception as e:
            errors += 1
            if self.config.get('verbose'):
                print(f"[ORCHESTRATOR] Fatal error scanning {url}: {e}")
        
        return {
            'url': url,
            'findings': findings,
            'parameters_tested': parameters_tested,
            'modules_run': modules_run,
            'errors': errors
        }
    
    async def _should_skip_header_checks(self, url: str) -> bool:
        """Determine if we should skip header checks for this URL (async-safe).
        
        Headers are domain-level, so we only need to check once per domain.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if we should skip header checks
        """
        # Extract domain
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        # Thread-safe check and mark
        async with self._domain_lock:
            if domain in self._header_checked_domains:
                return True
            
            # Mark domain as checked
            self._header_checked_domains.add(domain)
            return False
    
    def _create_tracking_client(self, http_client: AsyncHTTPClient):
        """Create a client wrapper that tracks stats transparently.
        
        Args:
            http_client: AsyncHTTPClient wrapper
        
        Returns:
            Tracking client that looks like httpx.AsyncClient
        """
        class StatsTrackingClient:
            """Wrapper that looks like httpx.AsyncClient but tracks stats."""
            def __init__(self, wrapper):
                self.wrapper = wrapper
                self._client = wrapper.client
                # Pass through all httpx.AsyncClient attributes
                for attr in dir(self._client):
                    if not attr.startswith('_') and attr not in ['get', 'post', 'put', 'delete', 'patch', 'request']:
                        setattr(self, attr, getattr(self._client, attr))
            
            async def get(self, *args, **kwargs):
                return await self.wrapper.get(*args, **kwargs)
            
            async def post(self, *args, **kwargs):
                return await self.wrapper.post(*args, **kwargs)
            
            async def put(self, *args, **kwargs):
                return await self.wrapper.put(*args, **kwargs)
            
            async def delete(self, *args, **kwargs):
                return await self.wrapper.delete(*args, **kwargs)
            
            async def patch(self, *args, **kwargs):
                return await self.wrapper.patch(*args, **kwargs)
            
            async def request(self, *args, **kwargs):
                return await self.wrapper.request(*args, **kwargs)
        
        return StatsTrackingClient(http_client)
    
    def _get_prioritized_modules(self, parameter: Dict, context: Dict) -> List:
        """Get modules prioritized based on context.
        
        Args:
            parameter: Parameter to test
            context: Context information
            
        Returns:
            List of modules ordered by relevance
        """
        module_priorities = self._apply_contextual_rules(parameter, context)
        
        # Build ordered list
        prioritized = []
        module_map = {m.name(): m for m in self.modules}
        
        # Add prioritized modules first
        for module_name in module_priorities:
            if module_name in module_map:
                prioritized.append(module_map[module_name])
                del module_map[module_name]
        
        # Add remaining modules
        prioritized.extend(module_map.values())
        
        return prioritized
    
    def _apply_contextual_rules(self, parameter: Dict, context: Dict) -> List[str]:
        """Apply context-aware module selection and prioritization.
        
        Uses rule engine for flexible, configurable prioritization.
        
        Args:
            parameter: Parameter to test
            context: Context information (URL, method, etc)
            
        Returns:
            List of module names prioritized for this context
        """
        # Get available module names
        available_modules = [m.name() for m in self.modules]
        
        # Use rule engine to prioritize
        prioritized = self.rule_engine.prioritize_modules(
            parameter=parameter,
            context=context,
            available_modules=available_modules
        )
        
        return prioritized
