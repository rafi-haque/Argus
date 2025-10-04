"""Scanning orchestrator - manages the overall scan workflow.

ASYNC-ONLY ARCHITECTURE
Uses asyncio + httpx for high-performance concurrent scanning.
"""
from typing import Dict, List, Optional
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
        
        # Scan discovered endpoints
        print("🔍 Scanning for vulnerabilities...")
        findings = []
        urls_scanned = set()
        parameters_tested = 0
        modules_run = 0
        errors = 0
        
        # Use async HTTP client
        async with AsyncHTTPClient(self.config) as http_client:
            # Set authentication headers if configured
            if self.config.get('auth'):
                auth = self.config['auth']
                if auth['type'] == 'header':
                    http_client.client.headers[auth['name']] = auth['value']
            
            # Create stats tracking wrapper
            tracking_client = self._create_tracking_client(http_client)
            
            # Process each site map entry
            for entry in site_map:
                url = entry['url']
                urls_scanned.add(url)
                
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
                        
                        # Check which modules apply to this parameter
                        for module in prioritized_modules:
                            if module.check_applicable(parameter, context):
                                modules_run += 1
                                
                                try:
                                    # Run the module (async)
                                    module_findings = await module.scan(url, parameter, tracking_client)
                                    findings.extend(module_findings)
                                
                                except Exception as e:
                                    errors += 1
                                    if self.config.get('verbose'):
                                        print(f"Error in {module.name()} on {url}: {e}")
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
                    
                    for module in prioritized_modules:
                        if module.check_applicable(parameter, context):
                            modules_run += 1
                            
                            try:
                                module_findings = await module.scan(url, parameter, tracking_client)
                                findings.extend(module_findings)
                            
                            except Exception as e:
                                errors += 1
                                if self.config.get('verbose'):
                                    print(f"Error in {module.name()} on {url}: {e}")
            
            # Get HTTP stats
            http_stats = http_client.get_stats()
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
