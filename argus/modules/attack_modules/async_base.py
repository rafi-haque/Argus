"""Async base class for attack modules.

New async-first architecture for high-performance scanning.
All new modules should inherit from AsyncBaseAttackModule.
"""
from abc import ABC, abstractmethod
from typing import Dict, List
import httpx


class AsyncBaseAttackModule(ABC):
    """Async base class for all attack modules.
    
    Provides async-first interface for maximum concurrency and performance.
    """
    
    def __init__(self, config: dict):
        """Initialize with scanner config.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.timeout = config.get('timeout', 10.0)
        self.max_payloads = config.get('max_payloads_per_param', 20)
    
    @abstractmethod
    def name(self) -> str:
        """Return module name (e.g., 'sqli', 'xss').
        
        Returns:
            str: Module identifier
        """
        pass
    
    @abstractmethod
    def description(self) -> str:
        """Return human-readable description.
        
        Returns:
            str: Module description
        """
        pass
    
    @abstractmethod
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if this module should run on this parameter.
        
        Args:
            parameter: {'name': str, 'value': str, 'location': str}
            context: {'url': str, 'method': str, 'all_params': list}
        
        Returns:
            bool: True if module should test this parameter
        """
        pass
    
    @abstractmethod
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Async vulnerability scan on parameter.
        
        Args:
            url: Full URL to test
            parameter: Parameter dict with 'name', 'value', 'location'
            client: Async HTTP client (from AsyncHTTPClient)
        
        Returns:
            list: Findings list (empty if no vulnerabilities)
                  Each finding: {
                      'name': str,
                      'severity': str,
                      'url': str,
                      'parameter': str,
                      'payload': str,
                      'evidence': str,
                      'recommendation': str
                  }
        """
        pass
    
    async def scan_batch(self, targets: List[tuple], client: httpx.AsyncClient) -> List[Dict]:
        """Scan multiple targets concurrently.
        
        Args:
            targets: List of (url, parameter) tuples
            client: Async HTTP client
        
        Returns:
            list: All findings from batch scan
        """
        import asyncio
        
        tasks = [self.scan(url, param, client) for url, param in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results and filter out exceptions
        all_findings = []
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                if self.config.get('verbose'):
                    print(f"Scan error in {self.name()}: {result}")
        
        return all_findings


class HybridAttackModule(ABC):
    """Hybrid module that works with both sync and async interfaces.
    
    Use this for gradual migration. Eventually all modules should be pure async.
    """
    
    def __init__(self, config: dict):
        """Initialize with scanner config.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
        self.timeout = config.get('timeout', 10.0)
    
    @abstractmethod
    def name(self) -> str:
        """Return module name."""
        pass
    
    @abstractmethod
    def description(self) -> str:
        """Return description."""
        pass
    
    @abstractmethod
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if module applies."""
        pass
    
    # Sync interface (legacy)
    def scan(self, url: str, parameter: dict, session) -> List[Dict]:
        """Synchronous scan (blocks).
        
        This wraps the async scan method for backward compatibility.
        """
        import asyncio
        import httpx
        
        # Convert requests session to httpx client config
        client_config = {
            'timeout': httpx.Timeout(self.timeout),
            'follow_redirects': False,
            'verify': session.verify if hasattr(session, 'verify') else True,
        }
        
        async def run_async_scan():
            async with httpx.AsyncClient(**client_config) as client:
                return await self.scan_async(url, parameter, client)
        
        # Run async code in sync context
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(run_async_scan())
    
    # Async interface (preferred)
    @abstractmethod
    async def scan_async(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Async scan method (non-blocking).
        
        This is the actual implementation. The sync scan() method wraps this.
        """
        pass
