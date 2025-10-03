"""Scanning orchestrator - manages the overall scan workflow."""
from typing import Dict, List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests


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
        self.max_concurrent = config.get('performance', {}).get('max_concurrent', 5)
        self.request_delay = config.get('performance', {}).get('request_delay', 0.1)
    
    def run_scan(self, seed_url: str) -> Dict:
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
        
        session = requests.Session()
        
        # Set authentication
        if self.config.get('auth'):
            auth = self.config['auth']
            if auth['type'] == 'header':
                session.headers[auth['name']] = auth['value']
        
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
                    
                    # Check which modules apply to this parameter
                    for module in self.modules:
                        if module.check_applicable(parameter, context):
                            modules_run += 1
                            
                            try:
                                # Run the module
                                module_findings = module.scan(url, parameter, session)
                                findings.extend(module_findings)
                                
                                # Rate limiting
                                time.sleep(self.request_delay)
                            
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
                
                for module in self.modules:
                    if module.check_applicable(parameter, context):
                        modules_run += 1
                        
                        try:
                            module_findings = module.scan(url, parameter, session)
                            findings.extend(module_findings)
                            
                            time.sleep(self.request_delay)
                        
                        except Exception as e:
                            errors += 1
                            if self.config.get('verbose'):
                                print(f"Error in {module.name()} on {url}: {e}")
        
        # Calculate stats
        scan_duration = time.time() - start_time
        
        stats = {
            'urls_scanned': len(urls_scanned),
            'parameters_tested': parameters_tested,
            'modules_run': modules_run,
            'scan_duration': scan_duration,
            'errors': errors
        }
        
        return {
            'site_map': site_map,
            'findings': findings,
            'stats': stats
        }
    
    def _apply_contextual_rules(self, parameter: Dict, context: Dict) -> List[str]:
        """Apply context-aware module selection.
        
        Args:
            parameter: Parameter to test
            context: Context information (URL, method, etc)
            
        Returns:
            List of module names prioritized for this context
        """
        priorities = []
        
        param_name = parameter.get('name', '').lower()
        url = context.get('url', '').lower()
        
        # Login/auth forms - prioritize SQLi
        if any(keyword in param_name for keyword in ['user', 'pass', 'login', 'auth']):
            priorities = ['sqli', 'xss']
        # API endpoints - prioritize SQLi
        elif '/api/' in url or param_name in ['id', 'userid']:
            priorities = ['sqli', 'xss']
        # Search forms - prioritize XSS
        elif 'search' in param_name or 'query' in param_name or 'q' == param_name:
            priorities = ['xss', 'sqli']
        else:
            priorities = ['xss', 'sqli']
        
        return priorities
