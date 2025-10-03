# Data Model

## Overview
The scanner uses in-memory data structures for site mapping and findings. All structures are JSON-serializable for easy persistence and reporting.

## Site Map
Collection of discovered endpoints from crawling.

**Structure**:
```python
site_map = [
    {
        "url": "http://example.com/products?id=5",
        "method": "GET",
        "parameters": [
            {
                "name": "id",
                "value": "5",
                "location": "query"  # or "body", "header", "cookie"
            }
        ]
    }
]
```

**Fields**:
- `url`: Full URL string
- `method`: HTTP method (GET, POST, etc.)
- `parameters`: List of parameter objects

**Parameter Fields**:
- `name`: Parameter name
- `value`: Current/sample value
- `location`: Where parameter appears (query, body, header, cookie)

## Findings
Collection of detected vulnerabilities.

**Structure**:
```python
findings = [
    {
        "name": "SQL Injection - Boolean-Based",
        "severity": "High",
        "url": "http://example.com/search?q=test",
        "parameter": "q",
        "payload": "' OR '1'='1",
        "evidence": "Response differed significantly from baseline"
    }
]
```

**Fields**:
- `name`: Vulnerability type and variant
- `severity`: High/Medium/Low/Info
- `url`: Affected URL
- `parameter`: Parameter name that was vulnerable
- `payload`: Successful attack payload
- `evidence`: Detection evidence

## Configuration
Scanner settings and target scope.

**Structure**:
```python
config = {
    "seed_url": "http://localhost:3000",
    "auth": {
        "type": "header",  # or "cookie"
        "name": "Authorization",
        "value": "Bearer token123"
    },
    "scope": {
        "include_patterns": [r"^https?://localhost:3000"],
        "exclude_patterns": [r"/logout$", r"/admin"]
    },
    "performance": {
        "max_concurrent": 5,
        "request_delay": 0.1,
        "timeout": 10
    }
}
```

## Attack Module Results
Per-module scan results.

**Structure**:
```python
module_results = {
    "module_name": "sqli",
    "url": "http://example.com/search?q=test",
    "vulnerable_parameters": ["q"],
    "payloads_tested": ["' OR '1'='1", "' OR '1'='2"],
    "evidence": "Boolean responses differed by 1500 bytes"
}
```

## Relationships
- Site Map drives Orchestrator parameter iteration
- Orchestrator selects modules based on parameter context
- Modules return Findings
- Findings aggregated for Reporting

## Validation Rules
- URLs must be valid and in scope
- Parameters must have name, value, location
- Findings must have all required evidence fields
- Configuration must have valid seed_url