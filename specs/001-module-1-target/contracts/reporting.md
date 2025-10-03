# Contract: Reporting Interface

## Overview
The reporting engine presents findings to users in multiple formats with consistent structure.

## Interface Definition

### Class: BaseReporter
```python
class BaseReporter:
    def __init__(self, config: dict):
        """Initialize with output config"""
        pass

    def generate_report(self, findings: list, site_map: list, stats: dict) -> None:
        """Generate and output report
        
        Args:
            findings: List of finding dicts
            site_map: List of site map entries
            stats: Scan statistics dict
        """
        pass
```

## Output Formats

### CLI Format
- Color-coded console output
- Severity-based sorting (High first)
- Concise evidence display
- Progress indicators during scan
- Summary statistics

### JSON Format
- Structured data for tool integration
- Full findings with all metadata
- Site map and stats included
- JSON Lines format for streaming

## Finding Display
Each finding shows:
- **Vulnerability**: Name and severity
- **Location**: URL and parameter
- **Payload**: Successful attack vector
- **Evidence**: Detection proof

## Implementation Requirements
- Handle empty findings gracefully
- Sort by severity for priority
- Truncate long URLs/payloads for CLI
- Include timestamps and version info
- Support output to file or stdout
- Unicode-safe output

## Examples

### CLI Reporter
```
🔴 HIGH: SQL Injection - Boolean-Based
   URL: http://localhost:3000/rest/products/search?q=test
   Param: q
   Payload: ' OR '1'='1
   Evidence: Response size changed from 1500 to 3200 bytes

📊 Scan Complete
   URLs scanned: 45
   Vulnerabilities found: 3
   Duration: 12.3s
```

### JSON Reporter
```json
{
  "version": "1.0.0",
  "timestamp": "2025-10-04T10:30:00Z",
  "findings": [
    {
      "name": "SQL Injection - Boolean-Based",
      "severity": "High",
      "url": "http://localhost:3000/rest/products/search?q=test",
      "parameter": "q",
      "payload": "' OR '1'='1",
      "evidence": "Response size changed from 1500 to 3200 bytes"
    }
  ],
  "stats": {
    "urls_scanned": 45,
    "parameters_tested": 120,
    "scan_duration": 12.3
  }
}
```