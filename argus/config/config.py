"""Configuration management for Argus scanner."""
import os
from typing import Dict, Optional


class Config:
    """Configuration manager for scanner."""
    
    DEFAULT_CONFIG = {
        'performance': {
            'max_concurrent': 5,
            'request_delay': 0.1,
            'timeout': 10,
        },
        'crawler': {
            'max_depth': 3,
            'active': False,  # Requires Playwright installation
        },
        'scope': {
            'include_patterns': [],
            'exclude_patterns': [
                r'/logout$',
                r'/signout$',
                r'/delete',
                r'/remove',
            ]
        },
        'verbose': False,
    }
    
    @classmethod
    def load_config(cls, config_file: Optional[str] = None) -> Dict:
        """Load configuration from file or use defaults.
        
        Args:
            config_file: Path to config file (optional)
        
        Returns:
            dict: Configuration dictionary
        """
        config = cls.DEFAULT_CONFIG.copy()
        
        if config_file and os.path.exists(config_file):
            # TODO: Implement config file loading (JSON/YAML)
            pass
        
        # Override with environment variables
        if os.getenv('ARGUS_MAX_CONCURRENT'):
            config['performance']['max_concurrent'] = int(os.getenv('ARGUS_MAX_CONCURRENT'))
        
        if os.getenv('ARGUS_REQUEST_DELAY'):
            config['performance']['request_delay'] = float(os.getenv('ARGUS_REQUEST_DELAY'))
        
        if os.getenv('ARGUS_TIMEOUT'):
            config['performance']['timeout'] = int(os.getenv('ARGUS_TIMEOUT'))
        
        if os.getenv('ARGUS_VERBOSE'):
            config['verbose'] = os.getenv('ARGUS_VERBOSE').lower() in ['true', '1', 'yes']
        
        return config
    
    @classmethod
    def merge_config(cls, base_config: Dict, overrides: Dict) -> Dict:
        """Merge configuration dictionaries.
        
        Args:
            base_config: Base configuration
            overrides: Override values
        
        Returns:
            dict: Merged configuration
        """
        result = base_config.copy()
        
        for key, value in overrides.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = cls.merge_config(result[key], value)
            else:
                result[key] = value
        
        return result
