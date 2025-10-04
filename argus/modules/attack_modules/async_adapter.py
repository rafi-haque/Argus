"""Adapter to make sync modules work in async context.

This is a temporary bridge while we migrate all modules to async.
It wraps sync modules so they can be called from async code.
"""
import asyncio
from typing import Dict, List
import httpx
from .async_base import AsyncBaseAttackModule


class AsyncModuleAdapter(AsyncBaseAttackModule):
    """Wraps a synchronous module to work in async context."""
    
    def __init__(self, sync_module, config: dict):
        """Initialize adapter.
        
        Args:
            sync_module: Synchronous module instance to wrap
            config: Configuration dict
        """
        super().__init__(config)
        self.sync_module = sync_module
        self._session = None
    
    def name(self) -> str:
        """Return module name."""
        return self.sync_module.name()
    
    def description(self) -> str:
        """Return module description."""
        return self.sync_module.description()
    
    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if module applies to parameter."""
        return self.sync_module.check_applicable(parameter, context)
    
    async def scan(self, url: str, parameter: dict, client: httpx.AsyncClient) -> List[Dict]:
        """Async scan that runs sync module in thread pool.
        
        Args:
            url: Target URL
            parameter: Parameter to test
            client: Async HTTP client (not used directly)
        
        Returns:
            List of findings
        """
        # Create a sync requests session if needed
        if self._session is None:
            import requests
            self._session = requests.Session()
            
            # Copy headers from async client if possible
            if hasattr(client, 'headers'):
                for key, value in client.headers.items():
                    self._session.headers[key] = value
        
        # Run sync scan in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        findings = await loop.run_in_executor(
            None,
            self.sync_module.scan,
            url,
            parameter,
            self._session
        )
        
        return findings


def wrap_sync_module(sync_module, config: dict) -> AsyncModuleAdapter:
    """Wrap a synchronous module for async use.
    
    Args:
        sync_module: Sync module instance
        config: Configuration dict
    
    Returns:
        AsyncModuleAdapter instance
    """
    return AsyncModuleAdapter(sync_module, config)
