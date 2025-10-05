# Argus Web Vulnerability Scanner

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](#-testing)

Context-aware web security scanner with intelligent vulnerability detection.

## 🎯 Overview

Argus is an automated web vulnerability scanner that discovers common security vulnerabilities by understanding the application's context. This leads to fewer and more accurate findings than purely "dumb" fuzzers.

**Ethical Use Only:** This tool is for authorized security testing only. Using this tool without permission is illegal. You are responsible for your actions.

## ✨ Key Features

-   **Context-Aware Detection**: Smart payload selection based on parameter analysis.
-   **Modular Architecture**: Pluggable vulnerability detection modules.
-   **Developer-First**: Clear CLI and JSON output formats.
-   **Performance Optimized**: Concurrent scanning with rate limiting.
-   **Compliance Mapping**: OWASP Top 10, CWE, PCI-DSS, HIPAA.
-   **Database Integration**: Store and analyze scan history.

## Detected Vulnerabilities

-   Insecure HTTP Headers
-   SQL Injection (Boolean-based and Time-based)
-   Cross-Site Scripting (Reflected and DOM-based)
-   Open Redirects
-   CORS Misconfigurations
-   CSRF Vulnerabilities
-   Path Traversal
-   File Inclusion (LFI/RFI)
-   Command Injection
-   Server-Side Request Forgery (SSRF)
-   Insecure Deserialization
-   API Vulnerabilities
-   Information Disclosure

## 📦 Installation

### Prerequisites

-   Python 3.11 or higher
-   pip (Python package manager)
-   Git
-   Docker (for test target)

### Setup

```bash
# Clone the repository
git clone https://github.com/rafi-haque/Argus.git
cd Argus

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🚀 Quick Start

### 1. Setup Test Target (OWASP Juice Shop)

```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

### 2. Run a Basic Scan

```bash
python -m argus.main --url http://localhost:3000
```

## 📖 Usage

### Command-Line Options

```bash
python -m argus.main [OPTIONS]
```

**Required:**

-   `--url URL`: Target URL to scan

**Scanning:**

-   `--policy POLICY`: Scan policy: `quick`, `standard`, `comprehensive`, `custom` (default: `standard`)
-   `--modules MODULE [...]`: Specific modules to run (overrides policy)
-   `--max-concurrent N`: Maximum concurrent requests (default: 5)
-   `--rate-limit N`: Requests per second (default: 10)
-   `--timeout N`: Request timeout in seconds (default: 10)

**Scope:**

-   `--include-pattern PAT`: URL patterns to include (regex)
-   `--exclude-pattern PAT`: URL patterns to exclude (regex)
-   `--max-depth N`: Maximum crawl depth (default: 3)

**Output:**

-   `--json FILE`: Output results as JSON
-   `--verbose`: Enable verbose logging
-   `--quiet`: Suppress banner and progress

**Database:**

-   `--db FILE`: SQLite database for storing results
-   `--no-db`: Disable database storage

### Scan Policies

| Policy          | Speed         | Coverage   | Use Case                   |
| --------------- | ------------- | ---------- | -------------------------- |
| `quick`         | ⚡⚡⚡ Fast    | Basic      | Quick security checks, CI/CD |
| `standard`      | ⚡⚡ Moderate | Balanced   | Regular security audits    |
| `comprehensive` | ⚡ Thorough  | Complete   | Deep security assessment   |
| `custom`        | Variable      | Custom     | Define specific modules    |

## 📁 Project Structure

```
argus/
├── argus/                  # Core scanner package
│   ├── main.py            # CLI entry point
│   ├── http_utils.py      # HTTP client
│   ├── utils.py           # Utilities
│   ├── modules/           # Detection modules
│   ├── compliance/        # Compliance frameworks
│   ├── database/          # Storage layer
│   └── config/            # Configuration files
├── tools/                 # Utility scripts
├── examples/              # Example files
├── tests/                 # Test suite
├── docs/                  # Documentation
├── specs/                 # Project specifications
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## 🔬 Development

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/unit/
```

### Adding a New Attack Module

1.  **Create Module File**: Create a new module in `argus/modules/attack_modules/`.
2.  **Implement Module**: Inherit from `BaseAttackModule` and implement the required methods.
3.  **Add Contract Test**: Add a contract test in `tests/contract/`.
4.  **Register in Main**: Add your new module to the list in `argus/main.py`.

## ⚠️ Ethical Use Disclaimer

**IMPORTANT: This tool is designed for authorized security testing only.**

-   **Permission Required**: Only scan systems you own or have explicit written authorization to test.
-   **Unauthorized Access**: Using this tool against systems without permission is ILLEGAL.
-   **Responsibility**: You are solely responsible for how you use this tool.

The developers of Argus assume no liability for misuse of this tool. By using Argus, you agree to comply with all applicable laws and regulations.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.