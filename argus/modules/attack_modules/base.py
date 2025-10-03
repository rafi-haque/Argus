"""Base class for all attack modules."""
from abc import ABC, abstractmethod
from typing import Dict, List
import requests


class BaseAttackModule(ABC):
    """Base class that all attack modules must inherit from."""
    
    def __init__(self, config: dict):
        """Initialize with scanner config.
        
        Args:
            config: Scanner configuration dictionary
        """
        self.config = config
    
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
    def scan(self, url: str, parameter: dict, session: requests.Session) -> List[Dict]:
        """Perform vulnerability scan on parameter.
        
        Args:
            url: Full URL to test
            parameter: Parameter dict with 'name', 'value', 'location'
            session: Configured requests session
        
        Returns:
            list: Findings list (empty if no vulnerabilities)
                  Each finding: {
                      'name': str,
                      'severity': str,
                      'url': str,
                      'parameter': str,
                      'payload': str,
                      'evidence': str
                  }
        """
        pass
