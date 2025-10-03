"""HTTP utilities with retry logic and better error handling."""
import time
import requests
from typing import Optional, Dict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class HTTPClient:
    """HTTP client with retry logic and rate limiting."""
    
    def __init__(self, config: dict):
        """Initialize HTTP client with configuration.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.timeout = config.get('performance', {}).get('timeout', 10)
        self.request_delay = config.get('performance', {}).get('request_delay', 0.1)
        self.max_retries = config.get('performance', {}).get('max_retries', 3)
        self.session = self._create_session()
        self.last_request_time = 0
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry configuration.
        
        Returns:
            requests.Session: Configured session
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,  # Exponential backoff: 0s, 1s, 2s, 4s...
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Argus-Scanner/1.0 (Security Testing Tool)'
        })
        
        return session
    
    def _rate_limit(self):
        """Apply rate limiting between requests."""
        if self.request_delay > 0:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
        
        self.last_request_time = time.time()
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform GET request with retry logic.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.get()
        
        Returns:
            requests.Response or None if all retries failed
        """
        self._rate_limit()
        
        kwargs.setdefault('timeout', self.timeout)
        
        try:
            response = self.session.get(url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            if self.config.get('verbose'):
                print(f"Request failed: {url} - {e}")
            return None
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Perform POST request with retry logic.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for requests.post()
        
        Returns:
            requests.Response or None if all retries failed
        """
        self._rate_limit()
        
        kwargs.setdefault('timeout', self.timeout)
        
        try:
            response = self.session.post(url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            if self.config.get('verbose'):
                print(f"Request failed: {url} - {e}")
            return None
    
    def close(self):
        """Close the session."""
        self.session.close()


class ScanProgress:
    """Track and report scan progress."""
    
    def __init__(self, total_urls: int, total_params: int):
        """Initialize progress tracker.
        
        Args:
            total_urls: Total number of URLs to scan
            total_params: Total number of parameters to test
        """
        self.total_urls = total_urls
        self.total_params = total_params
        self.scanned_urls = 0
        self.tested_params = 0
        self.findings_count = 0
        self.errors = 0
        self.start_time = time.time()
    
    def update_url(self):
        """Increment scanned URLs counter."""
        self.scanned_urls += 1
    
    def update_param(self):
        """Increment tested parameters counter."""
        self.tested_params += 1
    
    def add_finding(self):
        """Increment findings counter."""
        self.findings_count += 1
    
    def add_error(self):
        """Increment errors counter."""
        self.errors += 1
    
    def get_progress_percentage(self) -> float:
        """Calculate overall progress percentage.
        
        Returns:
            float: Progress as percentage (0-100)
        """
        if self.total_urls == 0:
            return 0.0
        return (self.scanned_urls / self.total_urls) * 100
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time since start.
        
        Returns:
            float: Elapsed time in seconds
        """
        return time.time() - self.start_time
    
    def get_estimated_remaining(self) -> float:
        """Estimate remaining scan time.
        
        Returns:
            float: Estimated remaining time in seconds
        """
        if self.scanned_urls == 0:
            return 0.0
        
        elapsed = self.get_elapsed_time()
        rate = elapsed / self.scanned_urls
        remaining_urls = self.total_urls - self.scanned_urls
        
        return rate * remaining_urls
    
    def print_progress(self, verbose: bool = False):
        """Print current progress.
        
        Args:
            verbose: Show detailed progress info
        """
        if verbose:
            progress = self.get_progress_percentage()
            elapsed = self.get_elapsed_time()
            remaining = self.get_estimated_remaining()
            
            print(f"\r[{progress:.1f}%] URLs: {self.scanned_urls}/{self.total_urls} | "
                  f"Params: {self.tested_params} | Findings: {self.findings_count} | "
                  f"Elapsed: {elapsed:.1f}s | ETA: {remaining:.1f}s", end='', flush=True)
    
    def get_summary(self) -> Dict:
        """Get progress summary.
        
        Returns:
            dict: Summary statistics
        """
        return {
            'urls_scanned': self.scanned_urls,
            'parameters_tested': self.tested_params,
            'findings': self.findings_count,
            'errors': self.errors,
            'scan_duration': self.get_elapsed_time(),
            'completion_percentage': self.get_progress_percentage()
        }


def is_in_scope(url: str, scope_config: Dict) -> bool:
    """Check if URL is within configured scope.
    
    Args:
        url: URL to check
        scope_config: Scope configuration with include/exclude patterns
    
    Returns:
        bool: True if URL is in scope
    """
    import re
    from urllib.parse import urlparse
    
    parsed = urlparse(url)
    
    # Check include patterns
    include_patterns = scope_config.get('include_patterns', [])
    if include_patterns:
        matches_include = any(
            re.search(pattern, url) for pattern in include_patterns
        )
        if not matches_include:
            return False
    
    # Check exclude patterns
    exclude_patterns = scope_config.get('exclude_patterns', [])
    if exclude_patterns:
        matches_exclude = any(
            re.search(pattern, url) for pattern in exclude_patterns
        )
        if matches_exclude:
            return False
    
    return True
