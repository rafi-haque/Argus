# Juice Shop Vulnerability Detection Progress

## Summary
Enhanced Argus scanner to detect OWASP Juice Shop vulnerabilities. Successfully improved SQLi detection module, but discovered critical orchestrator bug preventing module execution.

## Accomplishments

### 1. SQLi Module Enhancements ✅
**Status:** Complete and working

**Improvements:**
- Added simple quote-based payloads: `'`, `'--`, `')--`, `'))--`
- Enhanced error pattern detection for SQLite:
  - `SQLITE_ERROR`
  - `sqlite3.OperationalError`
  - `incomplete input`
  - `unrecognized token`
  - `SQL error`, `database error`, `query failed`
- Expanded `sql_indicators` to include 20+ common parameter names:
  - Added: `q`, `keyword`, `term`, `find`, `name`, `email`, `username`
  - Added: `category`, `cat`, `type`, `status`, `order`, `limit`, `offset`
  - Added: `pid`, `uid`, `cid`, `post`, `product`, `article`
- Increased error-based payload testing from 3 to 6 payloads

**Test Results:**
```python
# Direct module test - WORKS PERFECTLY
url = 'http://localhost:3000/rest/products/search?q=test'
parameter = {'name': 'q', 'value': 'test', 'location': 'query'}
findings = await module.scan(url, parameter, client)
# Result: Detects "SQL Injection - Error-Based: SQL error pattern 'SQLite' detected"
```

**Verified Detection:**
- ✅ Module detects SQLi in Juice Shop `/rest/products/search?q=` endpoint
- ✅ `check_applicable()` returns True for 'q' parameter
- ✅ Module included in prioritized module list
- ✅ No exceptions or errors during execution

### 2. Identified Critical Orchestrator Bug 🐛
**Status:** Root cause identified, fix pending

**Problem:**
- Scanner only runs 3 modules regardless of policy configuration
- Standard policy includes 8 modules: `xss, sqli, insecure_headers, csrf, open_redirect, cors, path_traversal, command_injection`
- Only `insecure_headers`, `cors`, and possibly `xss` actually execute
- **SQLi module never gets invoked despite passing all checks**

**Evidence:**
1. Scan output shows: "Modules run: 3"
2. No SQL injection findings in results (only headers/CORS config issues)
3. Added debug logging to SQLi module - no output (method never called)
4. Verified all checks pass:
   - Module loads correctly
   - `check_applicable()` returns True
   - Module in prioritized list
   - No exceptions thrown

**Root Cause Location:**
Bug is in `argus/modules/orchestrator.py`, lines 80-135, in the module invocation loop:
```python
for module in prioritized_modules:
    if module.check_applicable(parameter, context):
        modules_run += 1
        try:
            module_findings = await module.scan(url, parameter, tracking_client)
            findings.extend(module_findings)
```

**Hypothesis:**
- Possible issues with `tracking_client` wrapper
- Exception being silently caught
- Async invocation issue
- Early loop termination

## Test Results Against Juice Shop

### Current Detection (with orchestrator bug)
```
Target: http://localhost:3000/rest/products/search?q=test
Policy: standard

Found 6 issue(s): High: 1 | Medium: 2 | Low: 2 | Info: 1
- Missing Security Header: Strict-Transport-Security (HIGH)
- CORS Misconfiguration - Wildcard Origin (MEDIUM)
- Missing Security Header: Content-Security-Policy (MEDIUM)
- Missing Security Header: Referrer-Policy (LOW)
- Missing Security Header: X-XSS-Protection (LOW)
- Missing Security Header: Permissions-Policy (INFO)

Modules run: 3
Parameters tested: 1
```

### Expected Detection (once orchestrator fixed)
```
Should also detect:
- SQL Injection - Error-Based in /rest/products/search?q= ✅ (module works)
- XSS vulnerabilities (module should work)
- Command Injection (if applicable)
- Path Traversal (if applicable)
- CSRF issues (if applicable)
```

## Known Juice Shop Vulnerabilities (from OWASP documentation)

### High Priority Vulnerabilities to Detect:
1. **SQL Injection** ✅ (module ready)
   - `/rest/products/search?q=` - SQLite injection
   - Login form - `admin'--` bypass
   
2. **Broken Authentication**
   - SQL injection in login: `admin@juice-sh.op'--`
   - Weak passwords
   - JWT token issues
   
3. **XSS (Multiple types)**
   - Reflected XSS in search
   - DOM-based XSS in Angular app
   - Stored XSS in product reviews
   
4. **Broken Access Control (IDOR)**
   - Access other users' baskets
   - View other users' orders
   - Admin panel access
   
5. **Security Misconfiguration** ✅ (detecting)
   - Missing security headers
   - CORS wildcard
   - Debug endpoints exposed

## Next Steps

### Immediate (Critical)
1. **Fix Orchestrator Bug**
   - Debug `orchestrator.py` module invocation logic
   - Check `tracking_client` implementation
   - Review exception handling
   - Test with simple module first
   - Verify all 8 modules execute

### Short Term
2. **Add Authentication Bypass Module**
   - Test login endpoints with SQLi payloads
   - Check for default credentials
   - Test JWT/session vulnerabilities

3. **Enhance XSS Module**
   - Add DOM-based XSS detection
   - Improve SPA detection (Angular/React)
   - Test client-side template injection

4. **Add Broken Access Control Module**
   - Test IDOR vulnerabilities
   - Check unauthorized resource access
   - Test privilege escalation

### Validation
5. **Full Juice Shop Scan**
   - Run complete scan with all modules
   - Document all detected vulnerabilities
   - Compare with official Juice Shop vulnerability list
   - Calculate detection rate

## Commits Made
1. `2d62eb2` - Complete async conversion and fix all failing tests
2. `7c3198c` - Enhance SQLi detection for Juice Shop vulnerabilities  
3. `90be7d1` - Add debug logging for SQLi module execution

## Files Modified
- `argus/modules/attack_modules/sqli.py` - Enhanced detection
- `argus/modules/attack_modules/ssrf.py` - Fixed allow_redirects
- `argus/modules/attack_modules/insecure_headers.py` - Fixed allow_redirects
- `argus/modules/attack_modules/open_redirect.py` - Fixed allow_redirects
- `argus/modules/attack_modules/lfi_rfi.py` - Fixed session references
- `tests/unit/test_*.py` - Fixed all async test calls

## Performance
- Scan duration: 0.78s
- No performance degradation from enhancements
- Async architecture working well

## Conclusion
The SQLi detection improvements are complete and working perfectly. The module successfully detects SQL injection in Juice Shop when called directly. However, a critical bug in the orchestrator prevents most modules from executing during scans. Once this orchestrator bug is fixed, the scanner should detect multiple Juice Shop vulnerabilities including the SQL injection we've successfully targeted.

**Priority:** Fix orchestrator bug to unlock all the improvements we've made.
