# Argus Quick Reference Card

## 🚀 Quick Start

```bash
# Standard scan (default)
python -m argus.main --url http://localhost:3000

# Quick scan for CI/CD
python -m argus.main --url http://localhost:3000 --policy quick

# Full comprehensive scan
python -m argus.main --url http://localhost:3000 --policy full
```

## 📋 Available Scan Policies

| Policy | Time | Modules | Use Case |
|--------|------|---------|----------|
| `quick` | 5-10min | 4 | CI/CD, Quick checks |
| `standard` | 20-30min | 8 | Regular testing |
| `full` | 1-2hrs | 12 | Comprehensive assessment |
| `api` | 15-20min | 6 | API security |
| `owasp-top10` | 45min | 10 | Compliance testing |
| `custom` | Variable | Custom | Specific needs |

## 🛡️ Vulnerability Modules (12 Total)

### Critical Severity
- **sqli** - SQL Injection (error, boolean, UNION, time-based)
- **xss** - Cross-Site Scripting (with browser validation)
- **ssrf** - Server-Side Request Forgery
- **lfi_rfi** - Local/Remote File Inclusion
- **insecure_deserialization** - Pickle, PHP, Java, YAML, XXE
- **command_injection** - OS Command Injection

### High Severity
- **api_vulnerabilities** - BOLA, Mass Assignment, Data Exposure
- **open_redirect** - URL Redirection

### Medium Severity
- **csrf** - Cross-Site Request Forgery
- **cors** - CORS Misconfiguration
- **path_traversal** - Directory Traversal
- **insecure_headers** - Missing Security Headers

## 🎯 Common Usage Patterns

```bash
# With authentication
python -m argus.main --url http://target.com \
    --auth-header "Authorization: Bearer TOKEN"

# Custom modules only
python -m argus.main --url http://target.com \
    --policy custom --modules ssrf,lfi_rfi,api_vulnerabilities

# JSON output
python -m argus.main --url http://target.com \
    --json results.json

# Verbose mode
python -m argus.main --url http://target.com --verbose

# Performance tuning
python -m argus.main --url http://target.com \
    --max-concurrent 10 --request-delay 0.05
```

## 🧠 Intelligent Features

### Contextual Rules (Automatic)
The scanner automatically prioritizes modules based on:

| Parameter | Priority Modules |
|-----------|------------------|
| `?file=` | Path Traversal → LFI/RFI → Command Injection |
| `?url=` | Open Redirect → SSRF → XSS |
| `?cmd=` | Command Injection → SQLi → XSS |
| `/api/` | SQLi → API Vulnerabilities → XSS |
| `?redirect=` | Open Redirect → SSRF → XSS |
| `?search=` | XSS → SQLi |
| `?data=` | Insecure Deserialization → XSS → SQLi |

### Browser Validation (XSS)
- Automatically validates XSS with headless Chrome
- Reduces false positives significantly
- Enable/disable: `config['use_browser_validation'] = True/False`

## 📊 Performance Tips

### Faster Scans
```bash
# Use quick policy
--policy quick

# Reduce concurrent requests (less aggressive)
--max-concurrent 3

# Increase delay (for rate-limited targets)
--request-delay 0.2
```

### More Thorough Scans
```bash
# Use full policy
--policy full

# Increase concurrency (faster but more aggressive)
--max-concurrent 10

# Reduce delay (faster)
--request-delay 0.05
```

## 🔒 Security Notes

### Required Permissions
- Always get written authorization before scanning
- Unauthorized scanning is illegal
- Use only on your own systems or with explicit permission

### Testing Environments
```bash
# Good: Your own systems
python -m argus.main --url http://localhost:3000

# Good: Authorized pen test
python -m argus.main --url http://client-authorized-system.com

# BAD: Unauthorized systems ❌
python -m argus.main --url http://random-website.com  # DON'T DO THIS
```

## 🧪 Testing Your Installation

```bash
# Run all tests
pytest tests/unit/ -v

# Quick smoke test
pytest tests/unit/test_advanced_modules.py::TestSSRFModule -v

# Check specific module
pytest tests/unit/test_sqli.py -v
```

## 📈 Understanding Results

### Severity Levels
- **Critical**: Remote Code Execution, Data Exfiltration (SSRF, Deserialization, LFI/RFI, Command Injection)
- **High**: Data Access, XSS, SQLi, API Vulnerabilities
- **Medium**: CSRF, CORS, Headers, Path Traversal
- **Low**: Information Disclosure

### False Positives
- XSS: Very low (browser validation)
- SQLi: Low (multi-method confirmation)
- API: Medium (may need manual verification)
- SSRF: Low (pattern and behavior-based)

## 🐛 Troubleshooting

### Playwright Issues
```bash
# Install browsers
python -m playwright install chromium

# Disable browser validation
# In code: config['use_browser_validation'] = False
```

### Performance Issues
```bash
# Reduce concurrency
--max-concurrent 3

# Increase delay
--request-delay 0.2

# Use lighter policy
--policy quick
```

### Module Not Found
```bash
# Install dependencies
pip install -r requirements.txt

# Check Python version
python --version  # Needs 3.8+
```

## 📚 Documentation

- **Full Guide**: `ENHANCEMENTS_DOCUMENTATION.md`
- **Implementation Details**: `IMPLEMENTATION_SUMMARY.md`
- **Original Features**: `NEW_MODULES_DOCUMENTATION.md`
- **Tests**: `tests/unit/test_advanced_modules.py`

## 🎓 Policy Selection Guide

**Choose Quick** when:
- Running in CI/CD pipeline
- Need results in 5-10 minutes
- Checking for obvious issues
- Testing frequently

**Choose Standard** when:
- Regular security testing
- Balanced speed/coverage needed
- General vulnerability assessment
- Most common use case

**Choose Full** when:
- Comprehensive security audit
- Time is not a constraint
- Pre-release security check
- Want maximum coverage

**Choose API** when:
- Testing REST APIs
- Testing GraphQL endpoints
- API-only applications
- Microservices

**Choose OWASP Top 10** when:
- Compliance requirement
- Penetration testing
- Security certification
- Following OWASP standards

**Choose Custom** when:
- Testing specific vulnerabilities
- Debugging/developing modules
- Unusual requirements
- Research purposes

## 💡 Pro Tips

1. **Start with Quick**: Get fast results, then dive deeper
2. **Use Contextual Rules**: They're automatic and make scans faster
3. **Enable Browser Validation**: Reduces XSS false positives
4. **Read the Evidence**: Each finding includes detailed evidence
5. **Test Locally First**: Use OWASP Juice Shop or DVWA
6. **Save JSON Output**: Better for automation and CI/CD
7. **Use Verbose Mode**: When debugging or learning
8. **Respect Rate Limits**: Adjust `--request-delay` if needed
9. **Review Findings**: Always manually verify before reporting
10. **Keep Updated**: Check for new modules and updates

## 🎯 Example Workflows

### CI/CD Integration
```bash
# Fast scan in pipeline
python -m argus.main --url $STAGING_URL \
    --policy quick \
    --json scan_results.json

# Fail pipeline if critical findings
if grep -q '"severity": "Critical"' scan_results.json; then
    exit 1
fi
```

### Pre-Release Security Check
```bash
# Comprehensive scan before release
python -m argus.main --url $STAGING_URL \
    --policy full \
    --json full_scan.json \
    --verbose

# Generate report
python tools/generate_report.py full_scan.json > security_report.html
```

### API Security Testing
```bash
# API-focused scan
python -m argus.main --url $API_URL \
    --policy api \
    --auth-header "Authorization: Bearer $TOKEN" \
    --json api_scan.json
```

## 📞 Getting Help

- **GitHub Issues**: Report bugs or request features
- **Documentation**: Read `ENHANCEMENTS_DOCUMENTATION.md`
- **Tests**: Check `tests/unit/` for examples
- **Code**: Well-commented source code

---

**Remember**: With great power comes great responsibility. Only scan authorized systems! 🔒

---

*Argus v2.0 - Smart, Fast, Comprehensive Vulnerability Scanning*
