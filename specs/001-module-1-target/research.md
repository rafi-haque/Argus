# Research: Web Vulnerability Scanner

## Technical Decisions

### HTTP Client
- **Choice**: `requests` library
- **Rationale**: Mature, widely used, supports sessions, proxies, SSL. Simple API for GET/POST with params.
- **Alternatives Considered**: `httpx` (async support, but overkill for initial sync implementation), `urllib3` (lower level, more boilerplate)

### HTML Parsing
- **Choice**: `BeautifulSoup` with `lxml` parser
- **Rationale**: Robust HTML parsing, handles malformed HTML well. Easy link extraction with CSS selectors.
- **Alternatives Considered**: `lxml` directly (faster but more complex), `html.parser` (built-in but slower and less forgiving)

### Headless Browser
- **Choice**: `playwright` (Python async API)
- **Rationale**: Cross-browser support, reliable JS execution detection, good community. Supports sync API for simplicity.
- **Alternatives Considered**: `selenium` (older, more verbose), `pyppeteer` (Chrome-only, less maintained)

### CLI Framework
- **Choice**: `argparse` (standard library)
- **Rationale**: No external dependencies, sufficient for URL input and basic flags.
- **Alternatives Considered**: `click` (more features but adds dependency), `fire` (auto-generation but less control)

### Testing Framework
- **Choice**: `pytest`
- **Rationale**: Standard for Python, good fixtures, parametrized tests, assertions.
- **Alternatives Considered**: `unittest` (built-in but verbose), `nose` (less active)

### Data Structures
- **Site Map**: List of dicts with url, method, parameters (list of dicts with name, value, location)
- **Findings**: List of dicts with name, severity, url, payload, evidence
- **Rationale**: JSON-serializable, easy to manipulate, matches spec requirements

### Vulnerability Detection Techniques
- **Insecure Headers**: Simple presence check against known secure headers
- **SQLi Boolean-Based**: Differential response comparison (true vs false payloads)
- **SQLi Time-Based**: Response time measurement with sleep payloads
- **XSS Reflected**: Payload injection and reflection detection in HTML
- **XSS DOM-Based**: JS execution monitoring via alert override in headless browser

### Safety Measures
- Rate limiting: Built-in delays between requests
- Ethical warnings: Prominent disclaimers in README and CLI
- Scope limiting: Regex-based include/exclude patterns
- No destructive payloads: All detection payloads are non-malicious

### Performance Considerations
- Concurrent scanning: Use `concurrent.futures` for parallel endpoint checking
- Request pooling: `requests.Session` for connection reuse
- Timeout handling: Configurable timeouts with retries
- Memory usage: In-memory structures, no persistence needed for MVP

## OWASP Juice Shop Setup
- Docker command: `docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop`
- Known vulnerabilities for testing: SQLi in search/login, XSS in feedback, missing headers
- Test URLs: http://localhost:3000 (main), /rest/products/search (SQLi), /#/contact (XSS)

## Development Environment
- Python 3.11 in virtual environment
- IDE: VS Code with Python extension
- Linting: flake8, black for formatting
- Pre-commit hooks for quality gates

## Risks & Mitigations
- False positives: Implement strict detection thresholds, manual verification
- Rate limiting blocks: Configurable delays, respect robots.txt
- JS-heavy sites: Fallback to passive-only mode if Playwright fails
- Large sites: Implement depth limits, focus on seed URL domain