"""Scan policy configuration for different scanning scenarios."""


class ScanPolicy:
    """Base scan policy class."""
    
    def __init__(self, name, description, modules, max_depth=3, max_pages=100, timeout=10):
        """Initialize scan policy.
        
        Args:
            name: Policy name
            description: Policy description
            modules: List of module names to enable
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            timeout: Request timeout in seconds
        """
        self.name = name
        self.description = description
        self.modules = modules
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.request_delay = 0.1
        self.max_concurrent = 5
    
    def to_dict(self):
        """Convert policy to dict."""
        return {
            'name': self.name,
            'description': self.description,
            'modules': self.modules,
            'scope': {
                'max_depth': self.max_depth,
                'max_pages': self.max_pages
            },
            'performance': {
                'timeout': self.timeout,
                'request_delay': self.request_delay,
                'max_concurrent': self.max_concurrent
            }
        }


class QuickScanPolicy(ScanPolicy):
    """Quick scan policy - fast, surface-level scanning.
    
    - Only checks for common, easy-to-detect vulnerabilities
    - Minimal crawling depth
    - Fast timeouts
    - Good for initial reconnaissance or CI/CD pipelines
    """
    
    def __init__(self):
        super().__init__(
            name="quick",
            description="Fast surface-level scan for common vulnerabilities",
            modules=[
                'insecure_headers',
                'xss',
                'open_redirect',
                'cors',
            ],
            max_depth=1,
            max_pages=25,
            timeout=5
        )
        self.request_delay = 0.05  # Faster


class StandardScanPolicy(ScanPolicy):
    """Standard scan policy - balanced scanning.
    
    - Checks most common vulnerabilities
    - Moderate crawling depth
    - Standard timeouts
    - Good for regular security testing
    """
    
    def __init__(self):
        super().__init__(
            name="standard",
            description="Balanced scan covering common vulnerabilities",
            modules=[
                'xss',
                'sqli',
                'insecure_headers',
                'csrf',
                'open_redirect',
                'cors',
                'path_traversal',
                'command_injection',
                'auth_bypass',
            ],
            max_depth=3,
            max_pages=100,
            timeout=10
        )


class FullScanPolicy(ScanPolicy):
    """Full scan policy - comprehensive scanning.
    
    - Checks all vulnerabilities
    - Deep crawling
    - Longer timeouts for time-based detection
    - Good for thorough security assessments
    """
    
    def __init__(self):
        super().__init__(
            name="full",
            description="Comprehensive scan testing all vulnerability types",
            modules=[
                'xss',
                'sqli',
                'insecure_headers',
                'csrf',
                'open_redirect',
                'cors',
                'path_traversal',
                'command_injection',
                'ssrf',
                'lfi_rfi',
                'insecure_deserialization',
                'api_vulnerabilities',
                'auth_bypass',
            ],
            max_depth=5,
            max_pages=250,
            timeout=15
        )
        self.request_delay = 0.15  # More careful


class APIScanPolicy(ScanPolicy):
    """API-focused scan policy.
    
    - Focuses on API-specific vulnerabilities
    - Less crawling, more testing
    - Good for REST APIs and GraphQL endpoints
    """
    
    def __init__(self):
        super().__init__(
            name="api",
            description="API-focused scan for REST and GraphQL endpoints",
            modules=[
                'api_vulnerabilities',
                'sqli',
                'insecure_deserialization',
                'ssrf',
                'insecure_headers',
                'cors',
            ],
            max_depth=2,
            max_pages=50,
            timeout=10
        )


class OWASPTop10Policy(ScanPolicy):
    """OWASP Top 10 focused scan policy.
    
    - Covers OWASP Top 10 vulnerabilities
    - Comprehensive but focused
    - Good for compliance testing
    """
    
    def __init__(self):
        super().__init__(
            name="owasp-top10",
            description="Scan focused on OWASP Top 10 vulnerabilities",
            modules=[
                'sqli',  # A03:2021-Injection
                'xss',  # A03:2021-Injection
                'command_injection',  # A03:2021-Injection
                'insecure_deserialization',  # A08:2021-Software and Data Integrity Failures
                'ssrf',  # A10:2021-Server-Side Request Forgery
                'lfi_rfi',  # A01:2021-Broken Access Control
                'api_vulnerabilities',  # A01:2021-Broken Access Control
                'csrf',  # A01:2021-Broken Access Control
                'insecure_headers',  # A05:2021-Security Misconfiguration
                'cors',  # A05:2021-Security Misconfiguration
            ],
            max_depth=4,
            max_pages=150,
            timeout=12
        )


class CustomScanPolicy(ScanPolicy):
    """Custom scan policy - user-defined configuration."""
    
    def __init__(self, modules=None, max_depth=3, max_pages=100, timeout=10):
        """Initialize custom policy.
        
        Args:
            modules: List of module names to enable (None = all)
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            timeout: Request timeout
        """
        if modules is None:
            modules = [
                'xss', 'sqli', 'insecure_headers', 'csrf', 'open_redirect',
                'cors', 'path_traversal', 'command_injection', 'ssrf',
                'lfi_rfi', 'insecure_deserialization', 'api_vulnerabilities'
            ]
        
        super().__init__(
            name="custom",
            description="Custom user-defined scan policy",
            modules=modules,
            max_depth=max_depth,
            max_pages=max_pages,
            timeout=timeout
        )


# Policy registry
POLICIES = {
    'quick': QuickScanPolicy,
    'standard': StandardScanPolicy,
    'full': FullScanPolicy,
    'api': APIScanPolicy,
    'owasp-top10': OWASPTop10Policy,
    'custom': CustomScanPolicy,
}


def get_policy(policy_name, **kwargs):
    """Get a scan policy by name.
    
    Args:
        policy_name: Policy name ('quick', 'standard', 'full', 'api', 'owasp-top10', 'custom')
        **kwargs: Additional arguments for custom policy
    
    Returns:
        ScanPolicy: Policy instance
    
    Raises:
        ValueError: If policy name is invalid
    """
    if policy_name not in POLICIES:
        raise ValueError(
            f"Invalid policy: {policy_name}. "
            f"Valid policies: {', '.join(POLICIES.keys())}"
        )
    
    policy_class = POLICIES[policy_name]
    
    if policy_name == 'custom':
        return policy_class(**kwargs)
    else:
        return policy_class()


def list_policies():
    """List all available policies.
    
    Returns:
        dict: Policy name -> description mapping
    """
    policies = {}
    for name, policy_class in POLICIES.items():
        policy = policy_class() if name != 'custom' else policy_class([])
        policies[name] = policy.description
    return policies
