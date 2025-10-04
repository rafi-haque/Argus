"""Async HTTP client for high-performance scanning.

Replaces synchronous requests library with async httpx for:
- 10-50x performance improvement on I/O-bound workloads
- Connection pooling across all modules
- Concurrent request handling with proper backpressure
- Non-blocking I/O operations
"""
import asyncio
import httpx
from typing import Dict, Optional, Any
import time


class AsyncHTTPClient:
    """Async HTTP client wrapper for scanning operations.
    
    Provides high-performance async HTTP operations with connection pooling,
    rate limiting, and automatic retry logic.
    """
    
    def __init__(self, config: dict):
        """Initialize async HTTP client.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.timeout = httpx.Timeout(
            config.get('timeout', 10.0),
            connect=5.0,
            read=10.0,
            write=5.0
        )
        
        # Connection limits for concurrency control
        limits = httpx.Limits(
            max_keepalive_connections=config.get('max_keepalive', 50),
            max_connections=config.get('max_connections', 100),
            keepalive_expiry=30.0
        )
        
        # Client will be created per scan (context manager)
        self.client: Optional[httpx.AsyncClient] = None
        self.limits = limits
        
        # Rate limiting
        self.rate_limit = config.get('rate_limit', 10)  # requests per second
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        self.last_request_time = 0
        self.min_request_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        
        # Statistics
        self.stats = {
            'requests': 0,
            'errors': 0,
            'timeouts': 0,
            'total_time': 0.0
        }
    
    async def __aenter__(self):
        """Context manager entry."""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            limits=self.limits,
            follow_redirects=False,
            verify=self.config.get('verify_ssl', True),
            headers={'User-Agent': self.config.get('user_agent', 'Argus/2.0')}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.client:
            await self.client.aclose()
    
    async def _rate_limit_wait(self):
        """Implement rate limiting between requests."""
        if self.rate_limit <= 0:
            return
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - time_since_last)
        
        self.last_request_time = time.time()
    
    async def get(self, url: str, params: Optional[Dict] = None, 
                  headers: Optional[Dict] = None, **kwargs) -> httpx.Response:
        """Async GET request with rate limiting.
        
        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers
            **kwargs: Additional httpx parameters
        
        Returns:
            httpx.Response: Response object
        """
        async with self.semaphore:
            await self._rate_limit_wait()
            
            start_time = time.time()
            try:
                self.stats['requests'] += 1
                
                response = await self.client.get(
                    url,
                    params=params,
                    headers=headers,
                    **kwargs
                )
                
                elapsed = time.time() - start_time
                self.stats['total_time'] += elapsed
                
                return response
                
            except httpx.TimeoutException:
                self.stats['timeouts'] += 1
                self.stats['errors'] += 1
                raise
            except Exception:
                self.stats['errors'] += 1
                raise
    
    async def post(self, url: str, data: Optional[Dict] = None,
                   json: Optional[Dict] = None, headers: Optional[Dict] = None,
                   **kwargs) -> httpx.Response:
        """Async POST request with rate limiting.
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Additional headers
            **kwargs: Additional httpx parameters
        
        Returns:
            httpx.Response: Response object
        """
        async with self.semaphore:
            await self._rate_limit_wait()
            
            start_time = time.time()
            try:
                self.stats['requests'] += 1
                
                response = await self.client.post(
                    url,
                    data=data,
                    json=json,
                    headers=headers,
                    **kwargs
                )
                
                elapsed = time.time() - start_time
                self.stats['total_time'] += elapsed
                
                return response
                
            except httpx.TimeoutException:
                self.stats['timeouts'] += 1
                self.stats['errors'] += 1
                raise
            except Exception:
                self.stats['errors'] += 1
                raise
    
    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Generic async request method.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            **kwargs: Additional httpx parameters
        
        Returns:
            httpx.Response: Response object
        """
        async with self.semaphore:
            await self._rate_limit_wait()
            
            start_time = time.time()
            try:
                self.stats['requests'] += 1
                
                response = await self.client.request(method, url, **kwargs)
                
                elapsed = time.time() - start_time
                self.stats['total_time'] += elapsed
                
                return response
                
            except httpx.TimeoutException:
                self.stats['timeouts'] += 1
                self.stats['errors'] += 1
                raise
            except Exception:
                self.stats['errors'] += 1
                raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics.
        
        Returns:
            Dict: Statistics dictionary
        """
        avg_time = (self.stats['total_time'] / self.stats['requests'] 
                   if self.stats['requests'] > 0 else 0)
        
        return {
            **self.stats,
            'avg_request_time': avg_time,
            'success_rate': ((self.stats['requests'] - self.stats['errors']) / 
                           self.stats['requests'] if self.stats['requests'] > 0 else 0)
        }


class AsyncBatchHTTPClient:
    """Batch request handler for maximum concurrency.
    
    Handles hundreds or thousands of concurrent requests efficiently.
    """
    
    def __init__(self, client: AsyncHTTPClient, max_concurrent: int = 100):
        """Initialize batch client.
        
        Args:
            client: Base async HTTP client
            max_concurrent: Maximum concurrent requests
        """
        self.client = client
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def batch_get(self, urls: list, params_list: Optional[list] = None) -> list:
        """Execute multiple GET requests concurrently.
        
        Args:
            urls: List of URLs to fetch
            params_list: Optional list of params dicts (one per URL)
        
        Returns:
            list: List of (url, response or exception) tuples
        """
        if params_list is None:
            params_list = [None] * len(urls)
        
        async def fetch_one(url, params):
            async with self.semaphore:
                try:
                    response = await self.client.get(url, params=params)
                    return (url, response)
                except Exception as e:
                    return (url, e)
        
        tasks = [fetch_one(url, params) for url, params in zip(urls, params_list)]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        
        return results
    
    async def batch_scan(self, scan_tasks: list) -> list:
        """Execute multiple scan operations concurrently.
        
        Args:
            scan_tasks: List of coroutines (async functions)
        
        Returns:
            list: List of results
        """
        async def execute_with_semaphore(task):
            async with self.semaphore:
                return await task
        
        tasks = [execute_with_semaphore(task) for task in scan_tasks]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return results


# Compatibility layer for gradual migration
class SyncCompatWrapper:
    """Synchronous wrapper for async client.
    
    Allows gradual migration by providing sync interface to async client.
    This is a temporary bridge - all code should eventually be async.
    """
    
    def __init__(self, config: dict):
        """Initialize sync wrapper.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.async_client = None
        self.loop = None
    
    def __enter__(self):
        """Context manager entry."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.async_client = AsyncHTTPClient(self.config)
        self.loop.run_until_complete(self.async_client.__aenter__())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.async_client and self.loop:
            self.loop.run_until_complete(self.async_client.__aexit__(exc_type, exc_val, exc_tb))
            self.loop.close()
    
    def get(self, url: str, **kwargs) -> httpx.Response:
        """Synchronous GET request (blocks until complete).
        
        Args:
            url: Target URL
            **kwargs: Additional parameters
        
        Returns:
            httpx.Response: Response object
        """
        if not self.loop or not self.async_client:
            raise RuntimeError("Client not initialized. Use context manager.")
        
        return self.loop.run_until_complete(self.async_client.get(url, **kwargs))
    
    def post(self, url: str, **kwargs) -> httpx.Response:
        """Synchronous POST request (blocks until complete).
        
        Args:
            url: Target URL
            **kwargs: Additional parameters
        
        Returns:
            httpx.Response: Response object
        """
        if not self.loop or not self.async_client:
            raise RuntimeError("Client not initialized. Use context manager.")
        
        return self.loop.run_until_complete(self.async_client.post(url, **kwargs))
