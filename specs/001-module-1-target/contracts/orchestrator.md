# Contract: Orchestrator Interface

## Overview
The orchestrator manages the overall scanning process, coordinating between crawler, attack modules, and reporting.

## Interface Definition

### Class: ScannerOrchestrator
```python
class ScannerOrchestrator:
    def __init__(self, config: dict, modules: list):
        """Initialize with config and loaded attack modules"""
        pass

    def run_scan(self, seed_url: str) -> dict:
        """Execute full scanning workflow
        
        Args:
            seed_url: Starting URL for scan
        
        Returns:
            dict: {'site_map': list, 'findings': list, 'stats': dict}
        """
        pass
```

## Workflow Steps
1. **Crawl**: Discover site map from seed URL
2. **Analyze**: For each endpoint and parameter, determine applicable modules
3. **Dispatch**: Run selected modules concurrently where safe
4. **Collect**: Aggregate findings from all modules
5. **Report**: Generate outputs

## Contextual Analysis Rules
- **SQLi**: Parameters with numeric values, names containing 'id', 'search', 'query'
- **XSS**: All user-input parameters (query, body, headers)
- **Headers**: All URLs (endpoint-level check)
- **Custom Rules**: Configurable patterns for specific apps

## Concurrency Management
- Parallel scanning of different URLs
- Sequential scanning of same URL (to avoid interference)
- Rate limiting and delays between requests
- Thread pool sizing based on config

## Result Structure
```python
{
    'site_map': [/* site map entries */],
    'findings': [/* finding dicts */],
    'stats': {
        'urls_scanned': int,
        'parameters_tested': int,
        'modules_run': int,
        'scan_duration': float,
        'errors': int
    }
}
```

## Implementation Requirements
- Load attack modules dynamically
- Handle module failures gracefully
- Progress reporting and cancellation support
- Memory management for large site maps
- Configurable concurrency levels
- Error aggregation and reporting

## Examples

### Basic Orchestrator
- Crawl site passively
- For each parameter, run all applicable modules
- Collect and deduplicate findings

### Advanced Orchestrator
- Use active crawling for JS sites
- Apply smart contextual rules
- Parallel execution with progress bars
- Fallback strategies for failures