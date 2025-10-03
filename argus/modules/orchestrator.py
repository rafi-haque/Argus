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
                    
                    # Apply contextual rules to prioritize modules
                    prioritized_modules = self._get_prioritized_modules(parameter, context)
                    
                    # Check which modules apply to this parameter
                    for module in prioritized_modules:
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
                
                # Apply contextual rules for URL-level checks
                prioritized_modules = self._get_prioritized_modules(parameter, context)
                
                for module in prioritized_modules:
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
        
        This method analyzes the context (URL, parameter names, HTTP method, etc.)
        to intelligently prioritize which vulnerability checks to run first.
        This improves efficiency and accuracy by focusing on the most likely vulnerabilities.
        
        Args:
            parameter: Parameter to test
            context: Context information (URL, method, etc)
            
        Returns:
            List of module names prioritized for this context
        """
        priorities = []
        
        param_name = parameter.get('name', '').lower() if parameter.get('name') else ''
        url = context.get('url', '').lower()
        method = context.get('method', 'GET').upper()
        
        # URL/redirect parameters - prioritize Open Redirect and SSRF (check first!)
        if any(keyword in param_name for keyword in ['url', 'redirect', 'return', 'next', 'continue', 'dest', 'destination', 'redir', 'link']):
            priorities = ['open_redirect', 'ssrf', 'xss']
        
        # File upload/path parameters - prioritize Path Traversal and Command Injection
        elif any(keyword in param_name for keyword in ['file', 'path', 'dir', 'folder', 'upload', 'document']):
            priorities = ['path_traversal', 'lfi_rfi', 'command_injection', 'xss']
        
        # Command/system parameters - prioritize Command Injection
        elif any(keyword in param_name for keyword in ['cmd', 'command', 'exec', 'system', 'shell', 'ping']):
            priorities = ['command_injection', 'sqli', 'xss']
        
        # Login/auth forms - prioritize SQLi and CSRF
        elif any(keyword in param_name for keyword in ['user', 'pass', 'login', 'auth', 'email', 'username', 'password']):
            priorities = ['sqli', 'xss', 'csrf']
        
        # API endpoints - prioritize SQLi and API-specific vulns
        elif '/api/' in url or 'api.' in url:
            if param_name in ['id', 'userid', 'user_id', 'objectid', 'object_id']:
                priorities = ['sqli', 'api_vulnerabilities', 'xss']
            else:
                priorities = ['api_vulnerabilities', 'sqli', 'xss']
        
        # Search forms - prioritize XSS and SQLi
        elif any(keyword in param_name for keyword in ['search', 'query', 'q', 'keyword', 'term']):
            priorities = ['xss', 'sqli']
        
        # Data serialization parameters - prioritize Insecure Deserialization
        elif any(keyword in param_name for keyword in ['data', 'object', 'payload', 'serialized', 'json', 'xml']):
            priorities = ['insecure_deserialization', 'xss', 'sqli']
        
        # Form submissions (POST/PUT/PATCH) - check CSRF
        elif method in ['POST', 'PUT', 'PATCH', 'DELETE'] and not param_name:
            priorities = ['csrf', 'insecure_headers', 'cors']
        
        # ID parameters - prioritize SQLi
        elif param_name in ['id', 'userid', 'user_id', 'item_id', 'product_id', 'order_id']:
            priorities = ['sqli', 'xss']
        
        # Default prioritization
        else:
            priorities = ['xss', 'sqli', 'csrf']
        
        # Always check for insecure headers on URL-level checks
        if not param_name:
            if 'insecure_headers' not in priorities:
                priorities.append('insecure_headers')
        
        return priorities
