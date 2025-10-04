# Argus Web Vulnerability Scanner# 🔍 Argus Web Vulnerability Scanner# Argus Web Vulnerability Scanner



Context-aware web security scanner with intelligent vulnerability detection.



## Features<div align="center">## Overview



- **Context-Aware Detection** - Smart payload selection based on parameter analysisArgus is an automated web vulnerability scanner that discovers common security vulnerabilities by understanding the application's context, leading to fewer and more accurate findings than purely "dumb" fuzzers.

- **15+ Detection Modules** - SQL injection, XSS, CSRF, path traversal, and more

- **Async Architecture** - High-performance concurrent scanning**Context-Aware Web Security Scanner**

- **Compliance Mapping** - OWASP Top 10, CWE, PCI-DSS, HIPAA

- **Database Integration** - Store and analyze scan history## Key Features

- **Rule Engine** - Context-based module prioritization

- **Multiple Output Formats** - Terminal, JSON, HTML, Markdown[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)- **Context Over Volume**: Chooses the right payload for the right parameter



## Installation[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)- **Modular Architecture**: Pluggable vulnerability detection modules



```bash[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#testing)- **Developer-First**: Clear CLI and JSON output formats

# Clone repository

git clone https://github.com/yourusername/argus.git- **Safety First**: Built with ethical safeguards and warnings

cd argus

*Ethical use only • Written authorization required • Developer-first design*- **Performance Optimized**: Concurrent scanning with rate limiting

# Setup virtual environment

python -m venv .venv

source .venv/bin/activate  # Windows: .venv\Scripts\activate

</div>## Detected Vulnerabilities

# Install dependencies

pip install -r requirements.txt- Insecure HTTP Headers

```

---- SQL Injection (Boolean-based and Time-based)

## Quick Start

- Cross-Site Scripting (Reflected and DOM-based)

```bash

# Basic scan## 📋 Table of Contents

python -m argus.main --url https://example.com

## Installation

# Quick scan (fast, common vulnerabilities)

python -m argus.main --url https://example.com --policy quick- [Overview](#overview)



# Scan with database storage- [Key Features](#key-features)### Prerequisites

python -m argus.main --url https://example.com --db scans.db

- [Architecture](#architecture)- Python 3.11+

# Custom modules

python -m argus.main --url https://example.com --modules xss sqli cors- [Installation](#installation)- Docker (for test target)

```

- [Quick Start](#quick-start)

## Usage

- [Usage](#usage)### Setup

### Command Options

- [Project Structure](#project-structure)```bash

```

Required:- [Documentation](#documentation)# Clone the repository

  --url URL              Target URL to scan

- [Contributing](#contributing)git clone <repository-url>

Scanning:

  --policy POLICY        Scan policy: quick, standard, comprehensive, custom- [License](#license)cd argus

  --modules MODULE [..]  Specific modules to run

  --max-concurrent N     Maximum concurrent requests (default: 5)

  --rate-limit N         Requests per second (default: 10)

  --timeout N            Request timeout in seconds (default: 10)## 🎯 Overview# Set up virtual environment



Scope:python -m venv .venv

  --include-pattern PAT  URL patterns to include (regex)

  --exclude-pattern PAT  URL patterns to exclude (regex)Argus is a modern, context-aware web vulnerability scanner that intelligently detects security issues by understanding application context. Unlike traditional "spray and pray" scanners, Argus uses smart prioritization and context-based detection to deliver accurate findings with minimal false positives.source .venv/bin/activate  # On Windows: .venv\Scripts\activate

  --max-depth N          Maximum crawl depth (default: 3)



Output:

  --json FILE           Output results as JSON**Design Philosophy:**# Install dependencies

  --verbose             Enable verbose logging

  --quiet               Suppress banner and progress- ⚡ **Context Over Volume** - Smart payload selection based on parameter analysispip install -r requirements.txt



Database:- 🧩 **Modular Architecture** - Pluggable detection modules with prioritization```

  --db FILE             SQLite database for storing results

  --no-db               Disable database storage- 👨‍💻 **Developer-First** - Clean CLI, JSON output, and detailed reports

```

- 🔒 **Safety Built-In** - Ethical safeguards and rate limiting by default## Quick Start

### Scan Policies

- 🚀 **Performance Optimized** - Async architecture with concurrent scanning

- **quick** - Fast scan, common vulnerabilities only

- **standard** - Balanced scan, most vulnerabilities (default)### Setup Test Target (OWASP Juice Shop)

- **comprehensive** - Thorough scan, all modules

- **custom** - Manual module selection## ✨ Key Features```bash



### Detection Modulesdocker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop



- `insecure_headers` - Missing security headers### Detection Capabilities```

- `sqli` / `enhanced_sqli` - SQL injection

- `xss` - Cross-site scripting- 🛡️ **Security Headers** - Missing or misconfigured HTTP security headers

- `open_redirect` - Unvalidated redirects

- `cors` - CORS misconfigurations- 💉 **SQL Injection** - Boolean-based, time-based, and error-based detection### Run Basic Scan

- `csrf` - Cross-site request forgery

- `path_traversal` - Directory traversal- 🔓 **Cross-Site Scripting (XSS)** - Reflected, DOM-based, and stored XSS```bash

- `lfi_rfi` - File inclusion vulnerabilities

- `command_injection` - Command injection- 🔄 **Open Redirects** - Unvalidated redirect vulnerabilitiescd argus

- `ssrf` - Server-side request forgery

- `insecure_deserialization` - Deserialization bugs- 🌐 **CORS Misconfigurations** - Cross-origin resource sharing issuespython main.py --url http://localhost:3000

- `api_vulnerabilities` - API-specific issues

- 📝 **Information Disclosure** - Sensitive data leakage```

## Tools

- ⚙️ **Path Traversal** - Directory traversal vulnerabilities

### Database Manager

- 🔐 **Authentication Bypass** - Weak authentication mechanisms## Usage

```bash

# List scans- 🎭 **CSRF Vulnerabilities** - Cross-site request forgery issues

python tools/argus_db.py --db scans.db list

### Basic Scan

# Show scan details

python tools/argus_db.py --db scans.db show 1### Advanced Features```bash



# Compare scans- 🎯 **Context-Aware Prioritization** - Rule engine for smart module selectionpython main.py --url <target-url>

python tools/argus_db.py --db scans.db compare 1 2

- 🕷️ **Intelligent Crawler** - Deep site mapping with JavaScript handling```

# View trends

python tools/argus_db.py --db scans.db trend --days 30- 📊 **Compliance Reporting** - OWASP Top 10, CWE, PCI-DSS, HIPAA mapping

```

- 💾 **Database Integration** - SQLite/PostgreSQL for historical analysis**Example Output:**

### Compliance Reporter

- 📈 **Trend Analysis** - Track vulnerability changes over time```

```bash

# Generate compliance report- 🔄 **Scheduled Scans** - Automated recurring security checks⚠️  ETHICAL USE WARNING ⚠️

python tools/argus_compliance.py --db scans.db --scan-id 1

- 🎨 **Multiple Output Formats** - Terminal, JSON, HTML, Markdown reportsThis tool is for authorized security testing only.

# HTML report

python tools/argus_compliance.py --db scans.db --scan-id 1 \Using this tool without permission is ILLEGAL.

  --format html --output report.html

```## 🏗️ ArchitectureYou are responsible for your actions.



## Project Structure━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━



``````

argus/

├── argus/              # Core scanner packageargus/[*] Starting Argus Web Vulnerability Scanner

│   ├── main.py        # CLI entry point

│   ├── modules/       # Detection modules├── main.py                 # CLI entry point[*] Target: http://localhost:3000

│   ├── compliance/    # Compliance frameworks

│   ├── database/      # Storage layer├── http_utils.py          # Async HTTP client with rate limiting[*] Crawling site...

│   └── config/        # Configuration

├── tools/             # Utility scripts├── utils.py               # Shared utilities[*] Found 15 endpoints

├── examples/          # Example files

├── tests/             # Test suite├── modules/               # Attack modules[*] Running security checks...

└── docs/              # Documentation

```│   ├── orchestrator.py    # Scan coordination



## Documentation│   ├── rule_engine.py     # Context-aware prioritization━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━



- [Database Guide](docs/guides/DATABASE_GUIDE.md) - Storage and historical analysis│   ├── crawler.py         # Site mappingFINDINGS (3)

- [Compliance Guide](docs/guides/COMPLIANCE_GUIDE.md) - Framework mapping

- [Rule Engine Guide](docs/guides/RULE_ENGINE_GUIDE.md) - Prioritization│   ├── reporting.py       # Output formatters━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- [Quick Reference](docs/guides/QUICK_REFERENCE.md) - Common commands

- [Features](docs/guides/FEATURES.md) - Complete feature list│   ├── insecure_headers.py



## Testing│   ├── sqli.py[HIGH] SQL Injection - Boolean-Based



```bash│   ├── xss.py  URL: http://localhost:3000/rest/products/search?q=test

# Run all tests

pytest│   └── [12+ more modules]  Parameter: q



# Run specific test file├── compliance/            # Compliance mapping  Payload: test' OR '1'='1

pytest tests/unit/test_http_utils.py

│   ├── mapper.py  Evidence: Response differed significantly from baseline

# With coverage

pytest --cov=argus│   └── frameworks/

```

├── database/              # Storage layer[MEDIUM] Cross-Site Scripting - Reflected

### Test Target

│   ├── storage.py  URL: http://localhost:3000/search

```bash

# Start vulnerable test server│   ├── scheduler.py  Parameter: query

python examples/test_target.py

│   └── schema.py  Payload: <script>alert(1)</script>

# Scan test server

python -m argus.main --url http://127.0.0.1:8888 --policy standard└── config/                # Configuration  Evidence: Payload reflected in HTML response

```

    ├── policies.yaml

## Contributing

    └── rules.yaml[INFO] Insecure Headers

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

```  URL: http://localhost:3000

## Legal Disclaimer

  Missing Headers:

**ETHICAL USE ONLY**

## 📦 Installation    - Content-Security-Policy

This tool is for authorized security testing only. Unauthorized scanning is illegal.

    - X-Frame-Options

By using Argus, you agree to:

- Only scan systems you own or have written authorization to test### Prerequisites    - Strict-Transport-Security

- Comply with all applicable laws and regulations

- Take full responsibility for your actions- Python 3.11 or higher



## License- pip (Python package manager)━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━



MIT License - see LICENSE file for details.- GitScan completed in 45.2 seconds



---```



Made with ❤️ for security professionals### Setup


### With Authentication

```bash```bash

# Clone the repositorypython main.py --url <target-url> --auth-header "Authorization: Bearer <token>"

git clone https://github.com/yourusername/argus.git```

cd argus

**Example with Cookie Authentication:**

# Create virtual environment```bash

python -m venv .venvpython main.py --url http://localhost:3000 \

  --auth-header "Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Activate virtual environment```

source .venv/bin/activate  # On Windows: .venv\Scripts\activate

### JSON Output

# Install dependencies```bash

pip install -r requirements.txtpython main.py --url <target-url> --json output.json

``````



### Verify Installation**Sample JSON Output:**

```json

```bash{

python -m argus.main --help  "scan_info": {

```    "target": "http://localhost:3000",

    "start_time": "2025-10-04T10:30:00Z",

## 🚀 Quick Start    "end_time": "2025-10-04T10:30:45Z",

    "duration": 45.2

### Basic Scan  },

  "summary": {

```bash    "total": 3,

# Scan a target with default settings    "by_severity": {

python -m argus.main --url https://example.com      "critical": 0,

      "high": 1,

# Quick scan with common vulnerabilities only      "medium": 1,

python -m argus.main --url https://example.com --policy quick      "low": 0,

      "info": 1

# Full comprehensive scan    }

python -m argus.main --url https://example.com --policy comprehensive  },

```  "findings": [

    {

### With Database Storage      "module": "sqli",

      "severity": "high",

```bash      "name": "SQL Injection - Boolean-Based",

# Store results in database for historical analysis      "url": "http://localhost:3000/rest/products/search?q=test",

python -m argus.main --url https://example.com --policy standard --db scans.db      "parameter": "q",

      "payload": "test' OR '1'='1",

# View stored scans      "evidence": "Response differed significantly from baseline"

python tools/argus_db.py --db scans.db list    }

  ],

# Show detailed scan results  "site_map": [

python tools/argus_db.py --db scans.db show 1    {

```      "url": "http://localhost:3000",

      "method": "GET",

### Output Formats      "parameters": []

    },

```bash    {

# JSON output      "url": "http://localhost:3000/rest/products/search",

python -m argus.main --url https://example.com --json output.json      "method": "GET",

      "parameters": [

# Verbose logging        {

python -m argus.main --url https://example.com --verbose          "name": "q",

```          "value": "",

          "location": "query"

## 📖 Usage        }

      ]

### Command-Line Options    }

  ]

```bash}

python -m argus.main [OPTIONS]```



Required:### Advanced Options

  --url URL              Target URL to scan```bash

python main.py --url <target-url> \

Scanning:  --include-pattern "^https?://example.com" \

  --policy POLICY        Scan policy: quick, standard, comprehensive, custom  --exclude-pattern "/logout$" \

                        (default: standard)  --max-concurrent 5 \

  --modules MODULE [...]  Specific modules to run (overrides policy)  --request-delay 0.2

  --max-concurrent N     Maximum concurrent requests (default: 5)```

  --rate-limit N         Requests per second (default: 10)

  --timeout N            Request timeout in seconds (default: 10)### Scanning Specific Endpoints

```bash

Scope:# Scan only API endpoints

  --include-pattern PAT  URL patterns to include (regex)python main.py --url http://localhost:3000 \

  --exclude-pattern PAT  URL patterns to exclude (regex)  --include-pattern "^https?://localhost:3000/api"

  --max-depth N          Maximum crawl depth (default: 3)

# Exclude authentication endpoints

Output:python main.py --url http://localhost:3000 \

  --json FILE           Output results as JSON  --exclude-pattern "/(login|logout|signup)$"

  --verbose             Enable verbose logging```

  --quiet               Suppress banner and progress

### Verbose Mode

Database:```bash

  --db FILE             SQLite database for storing resultspython main.py --url <target-url> --verbose

  --no-db               Disable database storage```

```

This shows detailed crawling progress and module execution:

### Scan Policies```

[DEBUG] Crawling: http://localhost:3000

| Policy | Speed | Coverage | Use Case |[DEBUG] Found link: /products

|--------|-------|----------|----------|[DEBUG] Found link: /about

| `quick` | ⚡⚡⚡ Fast | Basic | Quick security checks, CI/CD |[DEBUG] Testing parameter 'q' for SQLi

| `standard` | ⚡⚡ Moderate | Balanced | Regular security audits |[DEBUG] Payload: test' OR '1'='1

| `comprehensive` | ⚡ Thorough | Complete | Deep security assessment |[DEBUG] Response: 200 OK (2500 bytes)

| `custom` | Variable | Custom | Define specific modules |```



### Examples## Architecture



```bash### Modules

# Quick scan for CI/CD pipeline- **Target & Scope Manager**: Defines scan boundaries and authentication

python -m argus.main --url https://staging.example.com --policy quick --quiet- **Crawler Engine**: Discovers attack surface (passive + active)

- **Scanning Orchestrator**: Manages scan workflow with contextual rules

# Standard scan with rate limiting- **Attack Modules**: Pluggable vulnerability detectors

python -m argus.main --url https://example.com --rate-limit 5 --max-concurrent 3- **Reporting Engine**: Generates CLI and JSON reports



# Comprehensive scan excluding admin pages## ⚠️ ETHICAL USE DISCLAIMER

python -m argus.main --url https://example.com --policy comprehensive \

  --exclude-pattern ".*/admin/.*"**IMPORTANT: This tool is designed for authorized security testing only.**



# Custom scan with specific modules### Legal Requirements

python -m argus.main --url https://example.com --policy custom \- **Permission Required**: Only scan systems you own or have explicit written authorization to test

  --modules xss sqli insecure_headers- **Unauthorized Access**: Using this tool against systems without permission is ILLEGAL

- **Responsibility**: You are solely responsible for how you use this tool

# Scan with database storage and compliance reporting

python -m argus.main --url https://example.com --db scans.db### Proper Use Cases

python tools/argus_compliance.py --db scans.db --scan-id 1 --format html✅ Testing your own applications

```✅ Authorized penetration testing engagements

✅ Bug bounty programs with explicit scope

## 📁 Project Structure✅ Educational environments with permission



```### Prohibited Use Cases

argus/❌ Scanning websites without authorization

├── argus/                  # Core scanner package❌ Attacking production systems without consent

│   ├── main.py            # CLI entry point❌ Using for malicious purposes

│   ├── http_utils.py      # HTTP client❌ Ignoring scope limitations

│   ├── utils.py           # Utilities

│   ├── modules/           # Detection modules**The developers of Argus assume no liability for misuse of this tool. By using Argus, you agree to comply with all applicable laws and regulations.**

│   ├── compliance/        # Compliance frameworks

│   ├── database/          # Storage layer## Development

│   └── config/            # Configuration files

├── tools/                 # Utility scripts### Project Structure

│   ├── argus_db.py        # Database manager```

│   ├── argus_compliance.py # Compliance reporterargus/

│   ├── argus_rules.py     # Rule engine tester├── argus/

│   └── demo_*.py          # Demonstration scripts│   ├── main.py                 # CLI entry point

├── examples/              # Example files│   ├── config/

│   ├── test_target.py     # Vulnerable test server│   │   └── config.py          # Configuration management

│   └── *_report.*         # Sample reports│   ├── modules/

├── tests/                 # Test suite│   │   ├── crawler.py         # Site map discovery

│   ├── unit/             # Unit tests│   │   ├── orchestrator.py    # Scan coordination

│   └── integration/      # Integration tests│   │   ├── reporting.py       # Output formatting

├── docs/                  # Documentation│   │   └── attack_modules/

│   ├── guides/           # User guides│   │       ├── base.py        # Module interface

│   ├── summaries/        # Feature summaries│   │       ├── insecure_headers.py

│   └── archived/         # Historical docs│   │       ├── sqli.py        # SQL Injection

├── specs/                 # Project specifications│   │       └── xss.py         # Cross-Site Scripting

├── requirements.txt       # Python dependencies│   └── utils.py               # Logging and errors

└── README.md             # This file├── tests/

```│   ├── contract/              # Interface tests

│   ├── integration/           # Workflow tests

## 📚 Documentation│   ├── unit/                  # Module tests

│   └── performance/           # Performance tests

Comprehensive documentation is available in the `docs/` directory:└── requirements.txt

```

### User Guides

- [Database Guide](docs/guides/DATABASE_GUIDE.md) - Historical analysis and storage### Running Tests

- [Compliance Guide](docs/guides/COMPLIANCE_GUIDE.md) - Regulatory framework mapping```bash

- [Rule Engine Guide](docs/guides/RULE_ENGINE_GUIDE.md) - Context-aware prioritization# Run all tests

- [Enhanced Crawler Guide](docs/guides/ENHANCED_CRAWLER_GUIDE.md) - Site mappingpytest tests/

- [Quick Reference](docs/guides/QUICK_REFERENCE.md) - Common commands and patterns

- [Features](docs/guides/FEATURES.md) - Complete feature list# Run specific test suite

pytest tests/contract/

### Technical Documentationpytest tests/integration/

- [Database Summary](docs/summaries/DATABASE_SUMMARY.md)pytest tests/unit/

- [Compliance Summary](docs/summaries/COMPLIANCE_SUMMARY.md)

- [Implementation Summary](docs/summaries/IMPLEMENTATION_SUMMARY.md)# Run with coverage

pytest --cov=argus tests/

### Demonstration

- [Demo Results](docs/DEMO_RESULTS.md) - Example scan outputs# Run performance tests

pytest tests/performance/ -v

## 🧪 Testing```



### Run Test Suite### Adding New Attack Module



```bash**Step 1: Create Module File**

# Run all tests```python

pytest# argus/modules/attack_modules/my_module.py

from .base import BaseAttackModule

# Run specific test file

pytest tests/unit/test_http_utils.pyclass MyModule(BaseAttackModule):

    def name(self):

# Run with coverage        return "my_module"

pytest --cov=argus --cov-report=html    

```    def description(self):

        return "My custom vulnerability check"

### Test Target    

    def check_applicable(self, parameter, context):

A vulnerable test application is included for safe testing:        # Return True if this check applies

        return True

```bash    

# Start test server    def scan(self, parameter, context):

python examples/test_target.py        # Perform vulnerability check

        findings = []

# Scan test server (in another terminal)        # ... detection logic ...

python -m argus.main --url http://127.0.0.1:8888 --policy standard        return findings

``````



## 🤝 Contributing**Step 2: Add Contract Test**

```python

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.# tests/contract/test_my_module.py

from argus.modules.attack_modules.my_module import MyModule

### Development Setup

def test_my_module_interface():

```bash    module = MyModule({})

# Clone and setup    assert hasattr(module, 'name')

git clone https://github.com/yourusername/argus.git    assert hasattr(module, 'description')

cd argus    assert hasattr(module, 'check_applicable')

python -m venv .venv    assert hasattr(module, 'scan')

source .venv/bin/activate```

pip install -r requirements.txt

**Step 3: Register in Main**

# Run tests```python

pytest# argus/main.py

from argus.modules.attack_modules.my_module import MyModule

# Check code style

flake8 argus/modules = [

black --check argus/    InsecureHeadersModule(config),

```    SQLiModule(config),

    XSSModule(config),

## 📄 License    MyModule(config),  # Add here

]

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.```



## ⚠️ Legal Disclaimer### Configuration



**ETHICAL USE ONLY**Create `config.json` in the project root:

```json

This tool is designed for security professionals and must only be used on systems you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions.{

  "performance": {

By using Argus, you agree to:    "max_concurrent": 5,

- Only scan systems you own or have written authorization to test    "request_delay": 0.1,

- Comply with all applicable laws and regulations    "timeout": 10

- Take full responsibility for your actions  },

- Use the tool ethically and responsibly  "crawler": {

    "max_depth": 3,

The authors and contributors are not responsible for misuse or damage caused by this tool.    "active": false

  },

## 🙏 Acknowledgments  "scope": {

    "include_patterns": ["^https?://localhost"],

- OWASP for security testing methodologies    "exclude_patterns": ["/logout$", "/delete"]

- The Python security community  }

- All contributors and testers}

```

## 📞 Support

Use with:

- 📧 Email: security@example.com```bash

- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/argus/issues)python main.py --url <target> --config config.json

- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/argus/discussions)```



---### Environment Variables

```bash

<div align="center"># Override configuration via environment

Made with ❤️ by security enthusiasts, for security professionalsexport ARGUS_MAX_CONCURRENT=10

</div>export ARGUS_VERBOSE=true


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
