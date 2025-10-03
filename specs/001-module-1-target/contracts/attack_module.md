# Contract: Attack Module Interface

## Overview
All attack modules must implement this interface for pluggability. The orchestrator will discover and load modules dynamically.

## Interface Definition

### Class: BaseAttackModule
```python
class BaseAttackModule:
    def __init__(self, config: dict):
        """Initialize with scanner config"""
        pass

    def name(self) -> str:
        """Return module name (e.g., 'sqli', 'xss')"""
        pass

    def description(self) -> str:
        """Return human-readable description"""
        pass

    def check_applicable(self, parameter: dict, context: dict) -> bool:
        """Check if this module should run on this parameter
        
        Args:
            parameter: {'name': str, 'value': str, 'location': str}
            context: {'url': str, 'method': str, 'all_params': list}
        
        Returns:
            bool: True if module should test this parameter
        """
        pass

    def scan(self, url: str, parameter: dict, session: requests.Session) -> list:
        """Perform vulnerability scan on parameter
        
        Args:
            url: Full URL to test
            parameter: Parameter dict
            session: Configured requests session
        
        Returns:
            list: Findings list (empty if no vulnerabilities)
        """
        pass
```

## Finding Structure
Each finding dict must contain:
```python
{
    'name': str,           # e.g., "SQL Injection - Boolean-Based"
    'severity': str,       # "High", "Medium", "Low", "Info"
    'url': str,            # Affected URL
    'parameter': str,      # Parameter name
    'payload': str,        # Successful payload
    'evidence': str        # Detection evidence
}
```

## Implementation Requirements
- Modules must be thread-safe for concurrent scanning
- No destructive actions (read-only testing)
- Handle timeouts and network errors gracefully
- Return empty list if no vulnerabilities found
- Log progress for observability

## Examples

### Insecure Headers Module
- `check_applicable`: Always True (checks all URLs)
- `scan`: GET request, check response headers

### SQLi Module
- `check_applicable`: True for query params with numeric values
- `scan`: Inject boolean payloads, compare responses

### XSS Module
- `check_applicable`: True for query/body params
- `scan`: Inject payloads, check for reflection/execution