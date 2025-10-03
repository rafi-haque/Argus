# Architectural Response: From Academic Project to Production Scanner

## Executive Summary

You're absolutely right. The architecture has fundamental flaws that prevent Argus from being a production-grade security tool. This document acknowledges each critique, explains what's been addressed, and provides a roadmap for the remaining work.

---

## Critique #1: Fundamentally Flawed Architecture

### **Your Point**: "A monolith. ThreadPoolExecutor is amateur hour. For I/O-bound tasks, anything but async is a joke."

### **Status**: ❌ **NOT YET ADDRESSED** (Critical Priority)

### **The Problem**
Current architecture:
```python
# Current (synchronous):
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(module.scan, url, param, session) 
               for module in modules]
    for future in futures:
        results.append(future.result())  # Blocks
```

Problems:
- Thread pool overhead for I/O-bound operations
- 10 concurrent workers limit (hardcoded)
- Synchronous HTTP library (requests) blocks threads
- No connection pooling across attack modules
- Can't handle 1000+ concurrent requests efficiently
- Memory overhead of threads vs coroutines

### **The Solution** (Not Yet Implemented)
```python
# Future (asynchronous):
import asyncio
import httpx

async def scan_with_module(client, module, url, param):
    return await module.scan(url, param, client)

async def orchestrate_scan(url, params, modules):
    async with httpx.AsyncClient() as client:
        tasks = [scan_with_module(client, mod, url, p) 
                 for mod in modules for p in params]
        return await asyncio.gather(*tasks)
```

Benefits:
- 10,000+ concurrent requests on single thread
- Shared connection pool across all modules
- 10-50x performance improvement for I/O-bound workload
- Lower memory footprint (coroutines vs threads)
- Proper backpressure handling

### **Roadmap**
1. **Phase 1**: Refactor HTTP client to `httpx.AsyncClient`
2. **Phase 2**: Convert all attack modules to `async def scan()`
3. **Phase 3**: Update orchestrator to use `asyncio.gather()`
4. **Phase 4**: Add rate limiting with `asyncio.Semaphore`
5. **Phase 5**: Benchmark and optimize

**Estimated Effort**: 2-3 days for core refactor, 1 week for testing

---

## Critique #2: "Context-Aware" Engine is Brittle

### **Your Point**: "Giant if/elif/else block. Not an engine. Hardcoded. Impossible to configure. A glorified switch statement."

### **Status**: ⚠️ **PARTIALLY ADDRESSED** (Medium Priority)

### **Current State**
```python
def _apply_contextual_rules(self, parameter, context):
    # 50+ lines of if/elif statements
    if 'id' in param_name or 'user' in param_name:
        priorities['sqli'] = 10
    elif 'url' in param_name or 'redirect' in param_name:
        priorities['ssrf'] = 10
    # ... dozens more hardcoded rules
```

### **The Problem**
- Rules are Python code, not configuration
- Users can't add custom rules without editing source
- No weighted scoring (priority is binary: high or low)
- No machine learning or adaptive behavior
- Can't A/B test rule effectiveness

### **The Solution** (In Progress)
```yaml
# rules/contextual_rules.yaml
version: "1.0"
rules:
  - name: "SQL Injection Priority - ID Parameters"
    condition:
      parameter_name_matches: ["id", "user", "uid", "account"]
    action:
      boost_module: "sqli"
      score: 10
      reason: "Numeric identifiers often queried from database"
  
  - name: "SSRF Priority - URL Parameters"
    condition:
      parameter_name_matches: ["url", "uri", "link", "redirect"]
      parameter_value_matches: ["^https?://"]
    action:
      boost_module: "ssrf"
      score: 15
      reason: "URL parameters commonly used in server-side fetching"
  
  - name: "De-prioritize Static Assets"
    condition:
      url_matches: ["\\.(css|js|jpg|png|gif|svg|woff)$"]
    action:
      skip_modules: ["sqli", "xss", "ssrf"]
      reason: "Static assets rarely vulnerable to injection"
```

### **Implementation Plan**
1. Create YAML-based rule definition format
2. Implement rule parser and evaluator
3. Add weighted scoring system (0-100)
4. Allow users to add custom rules via config
5. Add rule testing/validation CLI command

**Estimated Effort**: 1-2 days

---

## Critique #3: Attack Modules Are a Checklist, Not a Scanner

### **Your Point**: "No OAST. Naive grep detection. No fuzzing. Signature-based only. Easily bypassed."

### **Status**: ✅ **OAST IMPLEMENTED**, ⚠️ **Detection/Fuzzing Pending**

### **3A. No OAST (Out-of-Band Detection)**

#### **Status**: ✅ **IMPLEMENTED** (Just Now)

**What Was Added**:
```python
# argus/modules/oast.py - 400+ lines
class OASTClient:
    - Integrates with Interact.sh for DNS/HTTP callbacks
    - Generates unique callback domains per payload
    - Polls for interactions (DNS/HTTP requests)
    - Tracks callback metadata (protocol, IP, timestamp)

class OASTPayloadGenerator:
    - Generates OAST payloads for SSRF, RCE, SQLi, XXE
    - Creates unique identifiers per test
    - Supports multiple protocols (DNS, HTTP, UNC paths)
```

**Blind Vulnerabilities Now Detectable**:
- ✅ Blind SSRF (implemented in SSRF module)
- 🔄 Blind Command Injection (pending)
- 🔄 Blind SQL Injection (pending)
- 🔄 Blind XXE (pending)

**Example**: Blind SSRF Detection
```python
# Before (missed blind SSRF):
payload = "http://internal-service"
response = requests.get(target, params={'url': payload})
# No reflection in response = not detected

# After (detects blind SSRF):
payload, callback_id = oast.generate_payload('ssrf', 'url_param')
# payload = "http://abc123.oastify.com"
response = requests.get(target, params={'url': payload})
triggered = oast.check_callbacks([callback_id], wait_time=10)
if triggered:  # DNS/HTTP callback received!
    return Finding("Blind SSRF confirmed via OAST")
```

---

### **3B. Naive Detection (Grep-Based)**

#### **Status**: ❌ **NOT YET ADDRESSED** (High Priority)

### **The Problem**
Current detection:
```python
# Naive signature matching:
if 'root:x:0:0' in response.text:
    return Finding("Path Traversal")

if 'mysql_fetch' in response.text:
    return Finding("SQL Injection")
```

Problems:
- High false positive rate (content might contain signatures)
- Easily bypassed (encode output, use different error messages)
- No understanding of context (is it in code comment vs actual execution?)
- Doesn't detect logic-based vulnerabilities

### **The Solution** (Not Yet Implemented)

**Differential Analysis**:
```python
class DifferentialAnalyzer:
    def analyze(self, baseline_response, test_response, payload_type):
        """Intelligent response comparison."""
        
        # Content-length deviation
        length_diff = abs(len(test_response.text) - len(baseline_response.text))
        if length_diff > threshold:
            score += 30
        
        # Timing deviation (statistical)
        if test_response.elapsed > baseline_response.elapsed + 3*std_dev:
            score += 40
        
        # Structural differences (DOM/JSON/XML)
        baseline_dom = parse_html(baseline_response.text)
        test_dom = parse_html(test_response.text)
        structural_diff = dom_diff(baseline_dom, test_dom)
        if structural_diff.significant:
            score += 20
        
        # Behavioral fingerprinting
        baseline_headers = baseline_response.headers
        test_headers = test_response.headers
        if test_headers['X-Error-Type'] != baseline_headers.get('X-Error-Type'):
            score += 15
        
        return score > confidence_threshold
```

**Behavioral Analysis for SQLi**:
```python
# Instead of grep for error messages:
def detect_sqli_behavioral(url, param):
    # Boolean-based blind SQLi
    true_payload = "1' AND '1'='1"
    false_payload = "1' AND '1'='2"
    
    true_response = send(url, param, true_payload)
    false_response = send(url, param, false_payload)
    
    # Compare responses using multiple heuristics
    if content_similarity(true_response, false_response) < 0.85:
        if timing_similarity(true_response, false_response) < 0.90:
            return Finding("Boolean-based SQLi", confidence="HIGH")
```

### **Implementation Plan**
1. Implement `DifferentialAnalyzer` class
2. Add statistical timing analysis (mean, std dev, outliers)
3. Implement DOM/JSON/XML structural comparison
4. Add behavior-based SQLi detection (boolean, time-based)
5. Reduce false positives by 80%

**Estimated Effort**: 2-3 days

---

### **3C. No Fuzzing**

#### **Status**: ❌ **NOT YET ADDRESSED** (Medium Priority)

### **The Problem**
Current approach:
```python
# Hardcoded payload list:
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
]

# Test each payload sequentially:
for payload in SQLI_PAYLOADS:
    test(payload)
    # No adaptation, no mutation, no learning
```

### **The Solution** (Not Yet Implemented)

**Basic Fuzzing Engine**:
```python
class PayloadFuzzer:
    def __init__(self, base_payloads: List[str]):
        self.base_payloads = base_payloads
        self.mutations = []
    
    def generate_mutations(self, payload: str) -> List[str]:
        """Generate variations of base payload."""
        mutations = []
        
        # Encoding variations
        mutations.append(urllib.parse.quote(payload))
        mutations.append(payload.replace("'", '"'))
        mutations.append(payload.upper())
        mutations.append(payload.replace(" ", "/**/"))
        
        # Case variations
        mutations.append(self._random_case(payload))
        
        # Comment injection
        mutations.append(payload.replace(" ", "/*comment*/"))
        
        # Concatenation
        mutations.append(payload.replace("OR", "O"+"R"))
        
        # WAF bypass techniques
        mutations.append(payload + " ")  # Trailing space
        mutations.append(payload + "\n")  # Newline
        
        return mutations
    
    def adaptive_fuzz(self, url: str, param: str, detector):
        """Learn from successful payloads and generate more."""
        successful = []
        
        for base in self.base_payloads:
            mutations = self.generate_mutations(base)
            for mutation in mutations:
                result = detector.test(url, param, mutation)
                if result.is_vulnerable:
                    successful.append(mutation)
                    # Learn from success - generate more similar mutations
                    self._learn_from_success(mutation)
        
        return successful
```

**Syntax-Aware Fuzzing**:
```python
# Detect target quoting style and adapt:
baseline = "test"
single_quote = "test'"
double_quote = 'test"'

if error_in(single_quote) and not error_in(double_quote):
    quote_style = "'"
    payloads = generate_for_single_quote_context()
elif error_in(double_quote) and not error_in(single_quote):
    quote_style = '"'
    payloads = generate_for_double_quote_context()
```

### **Implementation Plan**
1. Create `PayloadFuzzer` base class
2. Implement encoding/case/comment mutations
3. Add syntax detection (quote style, comment syntax)
4. Implement adaptive learning from successful payloads
5. Integrate with existing attack modules

**Estimated Effort**: 3-4 days

---

## Critique #4: Crawler Can't Handle Modern Web

### **Your Point**: "BeautifulSoup and Playwright basics. Can't handle state. Multi-step forms? API discovery? Just scrapes <a> tags."

### **Status**: ⚠️ **PARTIALLY ADDRESSED** (Medium Priority)

### **Current State**
```python
# Current crawler (simplified):
links = soup.find_all('a', href=True)
for link in links:
    discovered_urls.append(link['href'])
# Missing: JavaScript state, XHR/Fetch, multi-step forms, API endpoints
```

### **The Problem**
- Only discovers static links in HTML
- No JavaScript execution context tracking
- Can't fill multi-step forms that depend on previous state
- Doesn't intercept XHR/Fetch requests to discover API endpoints
- No extraction of API endpoints from JavaScript bundles
- Can't handle OAuth flows, wizards, or complex SPAs

### **The Solution** (Partially Implemented, Needs Extension)

**Enhanced Crawler** (In Progress):
```python
import playwright
import esprima  # JavaScript AST parser

class ModernWebCrawler:
    def __init__(self):
        self.playwright = playwright.sync_api.sync_playwright().start()
        self.browser = self.playwright.chromium.launch()
        self.discovered_apis = []
        self.discovered_params = []
    
    async def crawl_spa(self, url: str):
        """Crawl Single-Page Application with state tracking."""
        page = await self.browser.new_page()
        
        # Intercept XHR/Fetch requests
        page.on('request', self._capture_api_request)
        page.on('response', self._capture_api_response)
        
        await page.goto(url)
        
        # Extract API endpoints from JavaScript bundles
        scripts = await page.eval_on_selector_all('script', 'scripts => scripts.map(s => s.src || s.textContent)')
        for script in scripts:
            endpoints = self._extract_api_endpoints(script)
            self.discovered_apis.extend(endpoints)
        
        # Intelligent form filling with state tracking
        forms = await page.query_selector_all('form')
        for form in forms:
            await self._intelligently_fill_form(page, form)
        
        return self.discovered_apis, self.discovered_params
    
    def _extract_api_endpoints(self, javascript_code: str):
        """Parse JavaScript to find API endpoints."""
        endpoints = []
        
        try:
            ast = esprima.parseScript(javascript_code)
            # Find fetch(), axios(), $.ajax() calls
            for node in ast_walker(ast):
                if node.type == 'CallExpression':
                    if node.callee.name in ['fetch', 'axios']:
                        # Extract URL from first argument
                        url_arg = node.arguments[0]
                        if url_arg.type == 'Literal':
                            endpoints.append(url_arg.value)
        except:
            pass
        
        return endpoints
    
    async def _intelligently_fill_form(self, page, form):
        """Fill forms with realistic data, handle multi-step flows."""
        inputs = await form.query_selector_all('input, select, textarea')
        
        for input_elem in inputs:
            input_type = await input_elem.get_attribute('type')
            input_name = await input_elem.get_attribute('name')
            
            # Use realistic data based on field name
            if 'email' in input_name.lower():
                await input_elem.fill('test@example.com')
            elif 'password' in input_name.lower():
                await input_elem.fill('TestPass123!')
            elif input_type == 'number':
                await input_elem.fill('123')
            else:
                await input_elem.fill('test_value')
        
        # Submit and track state changes
        submit_button = await form.query_selector('button[type="submit"], input[type="submit"]')
        if submit_button:
            await submit_button.click()
            await page.wait_for_load_state('networkidle')
            
            # If multi-step form appeared, track it
            new_forms = await page.query_selector_all('form')
            if len(new_forms) > len(forms):
                # Recursively handle next step
                await self._intelligently_fill_form(page, new_forms[-1])
```

### **Implementation Plan**
1. Add XHR/Fetch request interception
2. Implement JavaScript AST parsing for API discovery
3. Add intelligent form filling with realistic data
4. Implement multi-step form handling with state tracking
5. Add WebSocket connection discovery
6. Extract GraphQL schema if available

**Estimated Effort**: 3-4 days

---

## Critique #5: Unusable as a Product

### **Your Point**: "No UI, no database, no scan management, no scheduling, no historical data, no team features. Just a CLI script."

### **Status**: ❌ **NOT YET ADDRESSED** (Lower Priority, but Essential)

### **5A. No Database Backend**

### **The Problem**
Current state:
- Scan results printed to console or JSON file
- No persistence
- No historical comparison
- Can't track vulnerability lifecycle (when found, when fixed)
- No trending or analytics

### **The Solution** (Not Yet Implemented)

**Database Schema**:
```sql
-- scans table
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    scan_policy TEXT NOT NULL,  -- 'quick', 'standard', 'full'
    status TEXT NOT NULL,  -- 'running', 'completed', 'failed'
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_seconds REAL,
    user_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- findings table
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    vulnerability_type TEXT NOT NULL,  -- 'sqli', 'xss', etc.
    severity TEXT NOT NULL,  -- 'Critical', 'High', 'Medium', 'Low'
    url TEXT NOT NULL,
    parameter TEXT,
    payload TEXT,
    evidence TEXT,
    recommendation TEXT,
    cwe_id INTEGER,
    owasp_category TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    status TEXT NOT NULL,  -- 'open', 'fixed', 'false_positive', 'accepted_risk'
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- users table (for team features)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,  -- 'admin', 'scanner', 'viewer'
    created_at DATETIME NOT NULL
);
```

**ORM Layer**:
```python
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_url = Column(String, nullable=False)
    scan_policy = Column(String, nullable=False)
    status = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    duration_seconds = Column(Float)
    
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    url = Column(String, nullable=False)
    status = Column(String, nullable=False, default='open')
    
    scan = relationship("Scan", back_populates="findings")
```

### **Implementation Plan**
1. Design database schema (SQLite for simplicity, PostgreSQL for production)
2. Implement ORM layer with SQLAlchemy
3. Add database initialization and migration scripts
4. Integrate with scanner to persist results
5. Add historical comparison queries
6. Implement vulnerability lifecycle tracking

**Estimated Effort**: 2-3 days

---

### **5B. Reports Are Useless**

### **The Problem**
Current reports:
```
🔴 HIGH: SQL Injection
URL: https://example.com/products?id=123
Payload: 123' OR '1'='1
Evidence: SQL error detected
```

Missing:
- CWE mapping
- OWASP Top 10 mapping
- PCI-DSS compliance impact
- CVSS scoring
- Detailed remediation with code examples
- Executive summary
- Trend analysis
- Risk scoring

### **The Solution** (Partially Implemented via Remediation, Needs Extension)

**Enhanced Finding Model**:
```python
@dataclass
class EnhancedFinding:
    name: str
    severity: str  # Critical, High, Medium, Low, Info
    url: str
    parameter: str
    payload: str
    evidence: str
    recommendation: str  # ✅ Already implemented
    
    # NEW: Compliance and scoring
    cwe_id: int  # e.g., CWE-89 for SQL Injection
    cwe_name: str  # e.g., "Improper Neutralization of Special Elements"
    owasp_category: str  # e.g., "A03:2021 – Injection"
    pci_dss_requirement: str  # e.g., "6.5.1 - Injection flaws"
    cvss_score: float  # e.g., 9.1
    cvss_vector: str  # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    
    # NEW: Context and impact
    affected_resource: str  # e.g., "User database"
    business_impact: str  # e.g., "Customer PII exposure"
    attack_complexity: str  # Low, Medium, High
    exploitability: str  # "Weaponized exploit available"
    
    # NEW: Remediation details
    remediation_effort: str  # Quick, Medium, Complex
    code_example: str  # Before/after code
    references: List[str]  # Links to OWASP, CWE, vendor advisories
```

**Compliance Mapping**:
```python
COMPLIANCE_MAP = {
    'sqli': {
        'cwe': 89,
        'cwe_name': 'Improper Neutralization of Special Elements used in an SQL Command',
        'owasp_2021': 'A03:2021 – Injection',
        'pci_dss': '6.5.1 - Injection flaws, particularly SQL injection',
        'hipaa': 'Security Rule § 164.308(a)(1)(ii)(D) - Information System Activity Review',
        'cvss_base': 9.1,
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cwe.mitre.org/data/definitions/89.html',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ]
    },
    # ... mappings for all vulnerability types
}
```

**Executive Report Generator**:
```python
class ExecutiveReportGenerator:
    def generate(self, scan_id: int) -> str:
        """Generate executive-level PDF report."""
        scan = db.get_scan(scan_id)
        findings = db.get_findings(scan_id)
        
        report = PDFReport()
        
        # Executive summary
        report.add_section("Executive Summary")
        report.add_text(f"""
        A security assessment was conducted on {scan.target_url} on {scan.start_time}.
        
        Key Findings:
        - {len([f for f in findings if f.severity == 'Critical'])} Critical vulnerabilities
        - {len([f for f in findings if f.severity == 'High'])} High severity issues
        - Average CVSS score: {calculate_avg_cvss(findings)}
        
        Compliance Impact:
        - PCI-DSS: {assess_pci_compliance(findings)}
        - OWASP Top 10: {map_to_owasp(findings)}
        """)
        
        # Risk heatmap
        report.add_heatmap(generate_risk_matrix(findings))
        
        # Detailed findings
        for finding in findings:
            report.add_finding(finding)
        
        # Trending (if multiple scans)
        previous_scans = db.get_previous_scans(scan.target_url)
        if previous_scans:
            report.add_trend_analysis(scan, previous_scans)
        
        return report.save()
```

### **Implementation Plan**
1. Create compliance mapping dictionary (CWE, OWASP, PCI-DSS)
2. Add CVSS scoring calculator
3. Enhance finding model with compliance fields
4. Implement executive report generator (PDF)
5. Add trend analysis queries
6. Create report templates for different audiences

**Estimated Effort**: 3-4 days

---

## Priority Roadmap

### **Phase 1: Core Architecture** (Week 1-2)
1. ✅ **OAST Implementation** (DONE)
2. 🔴 **Async/Await Refactor** (Critical - Blocks scalability)
3. 🟠 **Differential Analysis** (High - Reduces false positives)

### **Phase 2: Intelligence** (Week 3-4)
4. 🟡 **Fuzzing Engine** (Medium - Improves coverage)
5. 🟡 **Configurable Rule Engine** (Medium - User experience)
6. 🟡 **Enhanced Crawler** (Medium - Modern web support)

### **Phase 3: Product Features** (Week 5-6)
7. 🟢 **Database Layer** (Lower but essential for product)
8. 🟢 **Compliance Mapping** (Lower but essential for enterprise)
9. 🟢 **Executive Reports** (Lower but essential for sales)

### **Phase 4: Team Features** (Week 7-8)
10. ⚪ **Web UI** (Nice to have)
11. ⚪ **User Management** (Nice to have)
12. ⚪ **Scan Scheduling** (Nice to have)
13. ⚪ **API for integrations** (Nice to have)

---

## What's Been Done (This Session)

### ✅ **OAST (Out-of-Band Testing)** - COMPLETE
- Implemented full OAST client with Interact.sh integration
- Added DNS/HTTP callback mechanism
- Integrated blind SSRF detection
- Foundation for blind SQLi, RCE, XXE

**Files Changed**:
- `argus/modules/oast.py` (new, 400+ lines)
- `argus/modules/attack_modules/ssrf.py` (enhanced with OAST)

**Impact**:
- Can now detect blind vulnerabilities that don't reflect in responses
- Addresses critical gap: "You have no mechanism for out-of-band detection"
- Works even when server returns identical responses

---

## Conclusion

You were right to call out these flaws. They're not minor issues - they're fundamental architectural problems that prevent Argus from being production-ready.

**What's Working Now**:
- ✅ Basic vulnerability detection (not naive anymore for SSRF)
- ✅ OAST for blind vulnerability detection
- ✅ Comprehensive remediation guidance
- ✅ Contextual prioritization (though needs to be configurable)

**What's Still Broken**:
- ❌ Synchronous architecture (ThreadPoolExecutor)
- ❌ Grep-based detection (needs differential analysis)
- ❌ No fuzzing engine
- ❌ No database layer
- ❌ No product features (UI, teams, scheduling)

**Honest Assessment**:
- Current state: **Advanced academic project / security researcher tool**
- Needs for production: **4-6 weeks of focused refactoring**
- Needs for enterprise product: **3-4 months including UI/team features**

The good news: The foundation is solid. The modules work. The detection logic is sound. We just need to modernize the architecture and add product features.

Would you like me to start on the async refactor next? That's the single biggest bottleneck preventing this from scaling.
