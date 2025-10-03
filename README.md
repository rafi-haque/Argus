# Argus Web Vulnerability Scanner

## Overview
Argus is an automated web vulnerability scanner that discovers common security vulnerabilities by understanding the application's context, leading to fewer and more accurate findings than purely "dumb" fuzzers.

## Key Features
- **Context Over Volume**: Chooses the right payload for the right parameter
- **Modular Architecture**: Pluggable vulnerability detection modules
- **Developer-First**: Clear CLI and JSON output formats
- **Safety First**: Built with ethical safeguards and warnings
- **Performance Optimized**: Concurrent scanning with rate limiting

## Detected Vulnerabilities
- Insecure HTTP Headers
- SQL Injection (Boolean-based and Time-based)
- Cross-Site Scripting (Reflected and DOM-based)

## Installation

### Prerequisites
- Python 3.11+
- Docker (for test target)

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd argus

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Setup Test Target (OWASP Juice Shop)
```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### Run Basic Scan
```bash
cd argus
python main.py --url http://localhost:3000
```

## Usage

### Basic Scan
```bash
python main.py --url <target-url>
```

**Example Output:**
```
⚠️  ETHICAL USE WARNING ⚠️
This tool is for authorized security testing only.
Using this tool without permission is ILLEGAL.
You are responsible for your actions.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[*] Starting Argus Web Vulnerability Scanner
[*] Target: http://localhost:3000
[*] Crawling site...
[*] Found 15 endpoints
[*] Running security checks...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINDINGS (3)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[HIGH] SQL Injection - Boolean-Based
  URL: http://localhost:3000/rest/products/search?q=test
  Parameter: q
  Payload: test' OR '1'='1
  Evidence: Response differed significantly from baseline

[MEDIUM] Cross-Site Scripting - Reflected
  URL: http://localhost:3000/search
  Parameter: query
  Payload: <script>alert(1)</script>
  Evidence: Payload reflected in HTML response

[INFO] Insecure Headers
  URL: http://localhost:3000
  Missing Headers:
    - Content-Security-Policy
    - X-Frame-Options
    - Strict-Transport-Security

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan completed in 45.2 seconds
```

### With Authentication
```bash
python main.py --url <target-url> --auth-header "Authorization: Bearer <token>"
```

**Example with Cookie Authentication:**
```bash
python main.py --url http://localhost:3000 \
  --auth-header "Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JSON Output
```bash
python main.py --url <target-url> --json output.json
```

**Sample JSON Output:**
```json
{
  "scan_info": {
    "target": "http://localhost:3000",
    "start_time": "2025-10-04T10:30:00Z",
    "end_time": "2025-10-04T10:30:45Z",
    "duration": 45.2
  },
  "summary": {
    "total": 3,
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 1
    }
  },
  "findings": [
    {
      "module": "sqli",
      "severity": "high",
      "name": "SQL Injection - Boolean-Based",
      "url": "http://localhost:3000/rest/products/search?q=test",
      "parameter": "q",
      "payload": "test' OR '1'='1",
      "evidence": "Response differed significantly from baseline"
    }
  ],
  "site_map": [
    {
      "url": "http://localhost:3000",
      "method": "GET",
      "parameters": []
    },
    {
      "url": "http://localhost:3000/rest/products/search",
      "method": "GET",
      "parameters": [
        {
          "name": "q",
          "value": "",
          "location": "query"
        }
      ]
    }
  ]
}
```

### Advanced Options
```bash
python main.py --url <target-url> \
  --include-pattern "^https?://example.com" \
  --exclude-pattern "/logout$" \
  --max-concurrent 5 \
  --request-delay 0.2
```

### Scanning Specific Endpoints
```bash
# Scan only API endpoints
python main.py --url http://localhost:3000 \
  --include-pattern "^https?://localhost:3000/api"

# Exclude authentication endpoints
python main.py --url http://localhost:3000 \
  --exclude-pattern "/(login|logout|signup)$"
```

### Verbose Mode
```bash
python main.py --url <target-url> --verbose
```

This shows detailed crawling progress and module execution:
```
[DEBUG] Crawling: http://localhost:3000
[DEBUG] Found link: /products
[DEBUG] Found link: /about
[DEBUG] Testing parameter 'q' for SQLi
[DEBUG] Payload: test' OR '1'='1
[DEBUG] Response: 200 OK (2500 bytes)
```

## Architecture

### Modules
- **Target & Scope Manager**: Defines scan boundaries and authentication
- **Crawler Engine**: Discovers attack surface (passive + active)
- **Scanning Orchestrator**: Manages scan workflow with contextual rules
- **Attack Modules**: Pluggable vulnerability detectors
- **Reporting Engine**: Generates CLI and JSON reports

## ⚠️ ETHICAL USE DISCLAIMER

**IMPORTANT: This tool is designed for authorized security testing only.**

### Legal Requirements
- **Permission Required**: Only scan systems you own or have explicit written authorization to test
- **Unauthorized Access**: Using this tool against systems without permission is ILLEGAL
- **Responsibility**: You are solely responsible for how you use this tool

### Proper Use Cases
✅ Testing your own applications
✅ Authorized penetration testing engagements
✅ Bug bounty programs with explicit scope
✅ Educational environments with permission

### Prohibited Use Cases
❌ Scanning websites without authorization
❌ Attacking production systems without consent
❌ Using for malicious purposes
❌ Ignoring scope limitations

**The developers of Argus assume no liability for misuse of this tool. By using Argus, you agree to comply with all applicable laws and regulations.**

## Development

### Project Structure
```
argus/
├── argus/
│   ├── main.py                 # CLI entry point
│   ├── config/
│   │   └── config.py          # Configuration management
│   ├── modules/
│   │   ├── crawler.py         # Site map discovery
│   │   ├── orchestrator.py    # Scan coordination
│   │   ├── reporting.py       # Output formatting
│   │   └── attack_modules/
│   │       ├── base.py        # Module interface
│   │       ├── insecure_headers.py
│   │       ├── sqli.py        # SQL Injection
│   │       └── xss.py         # Cross-Site Scripting
│   └── utils.py               # Logging and errors
├── tests/
│   ├── contract/              # Interface tests
│   ├── integration/           # Workflow tests
│   ├── unit/                  # Module tests
│   └── performance/           # Performance tests
└── requirements.txt
```

### Running Tests
```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/contract/
pytest tests/integration/
pytest tests/unit/

# Run with coverage
pytest --cov=argus tests/

# Run performance tests
pytest tests/performance/ -v
```

### Adding New Attack Module

**Step 1: Create Module File**
```python
# argus/modules/attack_modules/my_module.py
from .base import BaseAttackModule

class MyModule(BaseAttackModule):
    def name(self):
        return "my_module"
    
    def description(self):
        return "My custom vulnerability check"
    
    def check_applicable(self, parameter, context):
        # Return True if this check applies
        return True
    
    def scan(self, parameter, context):
        # Perform vulnerability check
        findings = []
        # ... detection logic ...
        return findings
```

**Step 2: Add Contract Test**
```python
# tests/contract/test_my_module.py
from argus.modules.attack_modules.my_module import MyModule

def test_my_module_interface():
    module = MyModule({})
    assert hasattr(module, 'name')
    assert hasattr(module, 'description')
    assert hasattr(module, 'check_applicable')
    assert hasattr(module, 'scan')
```

**Step 3: Register in Main**
```python
# argus/main.py
from argus.modules.attack_modules.my_module import MyModule

modules = [
    InsecureHeadersModule(config),
    SQLiModule(config),
    XSSModule(config),
    MyModule(config),  # Add here
]
```

### Configuration

Create `config.json` in the project root:
```json
{
  "performance": {
    "max_concurrent": 5,
    "request_delay": 0.1,
    "timeout": 10
  },
  "crawler": {
    "max_depth": 3,
    "active": false
  },
  "scope": {
    "include_patterns": ["^https?://localhost"],
    "exclude_patterns": ["/logout$", "/delete"]
  }
}
```

Use with:
```bash
python main.py --url <target> --config config.json
```

### Environment Variables
```bash
# Override configuration via environment
export ARGUS_MAX_CONCURRENT=10
export ARGUS_VERBOSE=true

python main.py --url <target>
```

## Troubleshooting

### Docker Issues
```bash
# Check if Juice Shop is running
docker ps | grep juice-shop

# View logs
docker logs juice-shop

# Restart container
docker restart juice-shop

# Stop and remove
docker stop juice-shop
docker rm juice-shop

# Recreate
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### Python Environment Issues
```bash
# Recreate virtual environment
deactivate
rm -rf .venv
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Install Playwright browsers (for active crawling)
playwright install
```

### Scanner Not Finding Vulnerabilities
1. **Check target accessibility:**
   ```bash
   curl -I http://localhost:3000
   ```

2. **Verify modules are loaded:**
   ```bash
   python main.py --version
   ```

3. **Enable verbose logging:**
   ```bash
   python main.py --url <target> --verbose
   ```

4. **Check scope patterns:**
   - Ensure `--include-pattern` matches your target
   - Verify `--exclude-pattern` isn't blocking endpoints

### Connection Errors
- **Timeout errors**: Increase `--timeout` value
- **Rate limiting**: Increase `--request-delay`
- **SSL errors**: Use `--insecure` flag (testing only!)

### Performance Issues
- **Slow scans**: Increase `--max-concurrent` (default: 5)
- **High memory usage**: Reduce `--max-depth` for crawler
- **Too many requests**: Increase `--request-delay`

## FAQ

**Q: Can I scan production websites?**
A: Only with explicit written authorization from the owner. Unauthorized scanning is illegal.

**Q: Why are some vulnerabilities not detected?**
A: Argus focuses on accuracy over volume. Some complex vulnerabilities may require manual testing.

**Q: How do I scan authenticated endpoints?**
A: Use `--auth-header` to provide authentication cookies or tokens.

**Q: Can I scan APIs?**
A: Yes! Argus works with REST APIs. Use JSON output for easier parsing.

**Q: What about false positives?**
A: Argus uses contextual rules to minimize false positives, but manual verification is recommended.

**Q: How fast can Argus scan?**
A: ~200 endpoints in <15 minutes. Performance depends on target response times and scan configuration.

**Q: Does Argus support HTTPS?**
A: Yes, HTTPS is fully supported with certificate verification.

**Q: Can I use this in CI/CD?**
A: Yes! Use JSON output mode and check exit codes:
```bash
python main.py --url $TARGET --json results.json
if [ $? -ne 0 ]; then exit 1; fi
```

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
[Add license information]

## Acknowledgments
- OWASP Juice Shop for test target
- Security research community
- Python security tools ecosystem

## Support
For issues and questions, please use the GitHub issue tracker.

---

**Remember: With great power comes great responsibility. Use Argus ethically and legally.**
