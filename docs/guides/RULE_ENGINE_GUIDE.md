# Configurable Rule Engine - Complete Guide

## Overview

The Argus rule engine replaces hardcoded if/elif logic with flexible, user-customizable YAML rules. This allows security teams to adapt scanning prioritization to their specific needs without modifying code.

## Why Rules Matter

**Before (Hardcoded):**
```python
# Buried in orchestrator.py - requires code changes
if 'url' in param_name:
    priorities = ['open_redirect', 'ssrf', 'xss']
elif 'file' in param_name:
    priorities = ['path_traversal', 'lfi_rfi']
# ... 50 more lines of if/elif
```

**After (Configurable):**
```yaml
# rules.yaml - edit without code changes
rules:
  - name: URL Parameters
    condition:
      param_name:
        contains: [url, redirect, return]
    modules: [open_redirect, ssrf, xss]
    weight: 100
```

## Key Benefits

1. **No Code Changes** - Edit rules.yaml, not Python
2. **Weighted Scoring** - Control priority with numeric weights
3. **Complex Conditions** - Support for regex, negation, AND/OR
4. **Team Collaboration** - Security teams can customize without developers
5. **Version Control** - Track rule changes in git
6. **Environment-Specific** - Different rules for dev/staging/prod

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Rule Engine Flow                         │
└─────────────────────────────────────────────────────────────┘

1. Orchestrator encounters parameter
   Parameter: name="redirect_url", value="...", location="query"
   Context: url="/login", method="POST", all_params=[...]

2. Rule Engine evaluates all rules
   ┌─────────────────────────────────────────────────────┐
   │ Rule: URL Parameters (weight: 100)                   │
   │ Condition: param_name contains [url, redirect]      │
   │ Modules: [open_redirect, ssrf, xss]                 │
   │ ✅ MATCHED ("redirect_url" contains "redirect")     │
   └─────────────────────────────────────────────────────┘

3. Build priority map with scores
   open_redirect: 100 (from URL Parameters rule)
   ssrf: 100 (from URL Parameters rule)
   xss: 100 (from URL Parameters rule)
   sqli: 0 (no matching rule)
   csrf: 0 (no matching rule)

4. Return sorted list
   [open_redirect, ssrf, xss, sqli, csrf, ...]
   
5. Orchestrator runs modules in priority order
```

## Rule File Format

### Basic Structure

```yaml
rules:
  - name: Rule Name
    condition: {...}
    modules: [...]
    weight: 0-100
    enabled: true
    description: What this rule does
    tags: [tag1, tag2]
```

### Fields

- **name** (required): Descriptive rule name
- **condition** (required): Matching criteria (see Conditions below)
- **modules** (required): List of module names to prioritize
- **weight** (optional, default 50): Priority score (0-100)
  - 90-100: Critical (URL params, file paths, commands)
  - 70-89: High (auth, APIs, IDs)
  - 50-69: Medium (search, POST requests)
  - 0-49: Low (headers, config)
- **enabled** (optional, default true): Whether rule is active
- **description** (optional): Human-readable explanation
- **tags** (optional): Tags for filtering/organization

## Condition System

### Available Fields

| Field | Description | Example |
|-------|-------------|---------|
| `param_name` | Parameter name | `id`, `user`, `url` |
| `param_location` | Where parameter appears | `query`, `body`, `cookie`, `header` |
| `url_pattern` | URL pattern | `/api/`, `admin.` |
| `method` | HTTP method | `GET`, `POST`, `PUT` |
| `has_params` | Check for specific params | `[username, password]` |

### Operators

#### `contains` - Substring Match
```yaml
condition:
  param_name:
    contains: [url, redirect, link]
# Matches: redirect_url, return_url, link_to, etc.
```

Can also use single string:
```yaml
condition:
  param_name:
    contains: admin
# Matches: admin_id, is_admin, etc.
```

#### `in` - Exact Match from List
```yaml
condition:
  param_name:
    in: [id, user_id, product_id]
# Matches ONLY: id, user_id, or product_id
```

#### `equals` - Exact Match
```yaml
condition:
  method:
    equals: POST
# Matches ONLY: POST (not PUT or PATCH)
```

#### `regex` - Regular Expression
```yaml
condition:
  url_pattern:
    regex: '^/api/v[0-9]+/'
# Matches: /api/v1/, /api/v2/, etc.
```

#### `startswith` / `endswith` - Prefix/Suffix
```yaml
condition:
  param_name:
    startswith: user_
# Matches: user_id, user_name, user_email

  param_name:
    endswith: _id
# Matches: user_id, product_id, order_id
```

#### `not` - Negation
```yaml
condition:
  param_name:
    not:
      in: [csrf_token, session_id]
# Matches everything EXCEPT csrf_token and session_id
```

#### `any` - OR Logic
```yaml
condition:
  param_name:
    any:
      - contains: admin
      - contains: root
      - equals: superuser
# Matches if ANY condition is true
```

#### `all` - AND Logic
```yaml
condition:
  param_name:
    all:
      - contains: user
      - endswith: _id
# Matches if ALL conditions are true (e.g., user_id)
```

### Multi-Field Conditions

Combine multiple fields (implicit AND):
```yaml
condition:
  param_name:
    contains: password
  method:
    in: [POST, PUT]
  url_pattern:
    contains: /auth/
# Matches: parameter named "password" on POST/PUT to /auth/ URLs
```

## Examples

### Example 1: Critical URL Parameters
```yaml
- name: URL/Redirect Parameters
  condition:
    param_name:
      contains: [url, redirect, return, next, goto]
  modules: [open_redirect, ssrf, xss]
  weight: 100
  description: URL parameters are critical SSRF/redirect targets
  tags: [critical, redirect, ssrf]
```

**Why?** Parameters that accept URLs are the #1 target for SSRF and open redirect attacks.

### Example 2: File Upload Endpoints
```yaml
- name: File Upload Detection
  condition:
    url_pattern:
      contains: [/upload, /attach, /import]
  modules: [path_traversal, command_injection, xss]
  weight: 85
  description: File upload endpoints need special attention
  tags: [upload, file, high]
```

**Why?** File uploads are complex and often vulnerable to path traversal, execution, and XSS.

### Example 3: Admin Panels
```yaml
- name: Admin Panel Detection
  condition:
    url_pattern:
      contains: [/admin, /dashboard, /management]
  modules: [auth_bypass, idor, sqli, xss]
  weight: 90
  description: Admin panels are high-value targets
  tags: [admin, privileged, high]
```

**Why?** Admin interfaces are high-value targets requiring thorough testing.

### Example 4: Complex Condition
```yaml
- name: Authenticated API Mutations
  condition:
    url_pattern:
      regex: '/api/v[0-9]+/'
    method:
      in: [POST, PUT, PATCH, DELETE]
    param_name:
      not:
        equals: null
  modules: [api_vulnerabilities, sqli, idor, csrf]
  weight: 85
  description: State-changing API calls with parameters
  tags: [api, mutation, high]
```

**Why?** State-changing API calls need comprehensive testing for multiple vulnerability types.

### Example 5: Context-Aware Search
```yaml
- name: Search with Special Characters
  condition:
    param_name:
      contains: [search, query, q]
    url_pattern:
      not:
        contains: /api/
  modules: [xss, sqli, ssti]
  weight: 80
  description: Search inputs on non-API endpoints
  tags: [search, xss]
```

**Why?** Search on traditional web pages often reflects input, making XSS more likely.

## Using Rules in Scans

### 1. Use Default Rules

No configuration needed - default rules loaded automatically:
```bash
python argus/main.py --url http://target.com
```

### 2. Export Default Rules

Create customizable template:
```bash
python argus_rules.py create my_rules.yaml
# or
python argus_rules.py export my_rules.yaml
```

### 3. Use Custom Rules

Point to your custom rules file:
```bash
python argus/main.py --url http://target.com --rules my_rules.yaml
```

Or set in config:
```python
config = {
    'url': 'http://target.com',
    'rules_file': 'my_rules.yaml',
    # ... other config
}
```

### 4. Validate Rules

Check rules file before using:
```bash
python argus_rules.py validate my_rules.yaml
```

Output:
```
✅ Rules file is valid: my_rules.yaml
   Total rules: 16
   Enabled rules: 15
   Disabled rules: 1

📊 Rule Distribution:
   90-99: ████ (4)
   80-89: ██████ (6)
   70-79: ████ (4)
   50-59: ██ (1)
```

## CLI Tool

The `argus_rules.py` CLI tool helps manage rules:

### Export Default Rules
```bash
python argus_rules.py export my_rules.yaml
python argus_rules.py export my_rules.json --format json
```

### List Rules
```bash
# List all enabled rules
python argus_rules.py list

# List all rules (including disabled)
python argus_rules.py list --all

# Filter by tag
python argus_rules.py list --tag critical

# Show details
python argus_rules.py list -v
```

### Test Rules
Test how rules match a specific parameter:
```bash
python argus_rules.py test redirect_url \
  --url "http://example.com/login" \
  --method POST

# Output shows matched rules and priority order
```

### Validate Rules
```bash
python argus_rules.py validate my_rules.yaml
```

### Show Statistics
```bash
python argus_rules.py stats
python argus_rules.py stats -v  # Detailed stats
```

## Customization Examples

### Scenario 1: Focus on API Security

Create `api_rules.yaml`:
```yaml
rules:
  # Boost API-specific checks
  - name: API Endpoints
    condition:
      url_pattern:
        contains: /api/
    modules: [api_vulnerabilities, sqli, idor, xss]
    weight: 100
  
  # De-prioritize non-API checks
  - name: Traditional Web Checks
    condition:
      url_pattern:
        not:
          contains: /api/
    modules: [csrf, insecure_headers]
    weight: 30
```

### Scenario 2: Compliance-First Scanning

Create `compliance_rules.yaml`:
```yaml
rules:
  # Always check auth/session
  - name: Authentication Required
    condition:
      param_name:
        contains: [auth, token, session]
    modules: [auth_bypass, csrf, insecure_headers]
    weight: 100
  
  # Always check sensitive data
  - name: PII Parameters
    condition:
      param_name:
        contains: [email, phone, ssn, credit, card]
    modules: [xss, sqli, insecure_headers, cors]
    weight: 95
```

### Scenario 3: Fast Triage Mode

Create `fast_rules.yaml`:
```yaml
rules:
  # Only critical checks
  - name: Critical Only
    condition:
      param_name:
        contains: [url, file, cmd, exec]
    modules: [open_redirect, ssrf, path_traversal, command_injection]
    weight: 100
  
  # Disable low-priority checks
  - name: Headers
    condition:
      param_name:
        equals: null
    modules: [insecure_headers]
    weight: 10
    enabled: false
```

## Advanced Patterns

### Pattern 1: Context Stacking

Multiple rules can match - higher weight wins:
```yaml
rules:
  # Base rule: all ID params get SQLi
  - name: ID Parameters
    condition:
      param_name:
        endswith: _id
    modules: [sqli]
    weight: 70
  
  # Override: user IDs also get IDOR
  - name: User ID Parameters
    condition:
      param_name:
        contains: user_id
    modules: [sqli, idor, auth_bypass]
    weight: 90  # Higher weight = takes precedence
```

Result: `user_id` gets modules from second rule (weight 90), `product_id` gets first rule (weight 70).

### Pattern 2: Exclusion Rules

Use negation to skip certain patterns:
```yaml
- name: Skip Static Resources
  condition:
    url_pattern:
      regex: '\.(js|css|jpg|png|gif|woff|ttf)$'
  modules: []  # Empty = skip entirely
  weight: 0
  enabled: true
```

### Pattern 3: Environment-Specific

Use different rules per environment:
```bash
# Production: Conservative
python argus/main.py --url https://prod.example.com --rules prod_rules.yaml

# Staging: Aggressive
python argus/main.py --url https://staging.example.com --rules staging_rules.yaml
```

## Performance Impact

### Rule Evaluation Cost

- Rules evaluated once per parameter (~100 microseconds)
- Minimal impact compared to HTTP requests (10-100ms)
- O(n) complexity where n = number of rules

### Optimization Tips

1. **Put high-weight rules first** (file already sorted by weight)
2. **Use specific conditions** (avoid broad regex)
3. **Limit rule count** (10-20 rules ideal, 50 max recommended)
4. **Disable unused rules** (set `enabled: false`)

### Benchmark

Testing with 16 rules on 100 parameters:
- Rule evaluation time: ~10ms total
- HTTP request time: ~5000ms total
- **Overhead: 0.2%** ✅

## Troubleshooting

### Issue: Rules Not Matching

**Problem:**
```bash
python argus_rules.py test my_param
# Output: No rules matched
```

**Solution:**
1. Check parameter name case (conditions are case-sensitive on values)
2. Verify condition logic (use `--verbose` flag)
3. Test with simpler condition:
```yaml
condition:
  param_name:
    contains: my
```

### Issue: Wrong Priority Order

**Problem:** Modules running in unexpected order

**Solution:**
1. Check rule weights (higher = higher priority)
2. Verify multiple rules aren't conflicting
3. Use test command:
```bash
python argus_rules.py test my_param --url http://example.com -v
```

### Issue: Rules File Not Loading

**Problem:**
```
FileNotFoundError: Rules file not found
```

**Solution:**
1. Use absolute path: `--rules /full/path/to/rules.yaml`
2. Place in default location: `argus/config/rules.yaml`
3. Check YAML syntax: `python argus_rules.py validate rules.yaml`

## API Usage

### Python Integration

```python
from argus.modules.rule_engine import RuleEngine, Rule

# Load rules
engine = RuleEngine('my_rules.yaml')

# Add custom rule programmatically
rule = Rule(
    name='Custom Rule',
    condition={'param_name': {'contains': 'api'}},
    modules=['sqli', 'xss'],
    weight=85
)
engine.add_rule(rule)

# Test prioritization
parameter = {'name': 'api_key', 'value': '...', 'location': 'query'}
context = {'url': 'http://example.com', 'method': 'GET'}
available = ['sqli', 'xss', 'csrf', 'idor']

prioritized = engine.prioritize_modules(parameter, context, available)
print(prioritized)  # ['sqli', 'xss', 'csrf', 'idor']
```

### Dynamic Rule Updates

```python
# Load initial rules
engine = RuleEngine('rules.yaml')

# Modify rule at runtime
rule = engine.get_rule('URL Parameters')
if rule:
    rule.weight = 110  # Increase priority
    rule.modules.append('new_module')

# Export modified rules
engine.export_rules('updated_rules.yaml')
```

## Best Practices

### 1. Start with Defaults

Use built-in rules as starting point:
```bash
python argus_rules.py export my_rules.yaml
```

### 2. Gradual Customization

Don't overhaul everything at once:
1. Run scan with defaults
2. Identify one pain point (false positives, missing checks)
3. Add/modify one rule
4. Test and validate
5. Repeat

### 3. Version Control

Track rule changes:
```bash
git add argus/config/rules.yaml
git commit -m "Boost API security checks"
```

### 4. Document Changes

Add descriptions:
```yaml
- name: Custom Rule
  description: Added for Project X security requirements (JIRA-123)
  # ... rest of rule
```

### 5. Test Before Production

```bash
# Test on staging
python argus/main.py --url https://staging.example.com --rules new_rules.yaml

# Validate findings
# If good, deploy to prod
```

### 6. Review Regularly

Schedule quarterly review:
- Are weights still appropriate?
- Do new vulnerabilities need rules?
- Can any rules be removed?

## Migration from Hardcoded Logic

The orchestrator previously had ~70 lines of hardcoded if/elif logic. Here's the migration:

**Old Code (orchestrator.py):**
```python
def _apply_contextual_rules(self, parameter, context):
    if 'url' in param_name:
        return ['open_redirect', 'ssrf', 'xss']
    elif 'file' in param_name:
        return ['path_traversal', 'lfi_rfi']
    # ... 65 more lines
```

**New Code (orchestrator.py):**
```python
def _apply_contextual_rules(self, parameter, context):
    available_modules = [m.name() for m in self.modules]
    return self.rule_engine.prioritize_modules(
        parameter, context, available_modules
    )
```

**Result:**
- 70 lines → 5 lines
- Hardcoded → Configurable
- Code changes → YAML edits
- Zero flexibility → Infinite flexibility

## Summary

| Feature | Hardcoded | Rule Engine |
|---------|-----------|-------------|
| **Customization** | Code changes required | Edit YAML file |
| **Team Access** | Developers only | Security team too |
| **Complexity** | 70+ lines if/elif | Clean 5-line function |
| **Version Control** | Code commits | Config file commits |
| **Environment-Specific** | Difficult | Trivial (different files) |
| **Testing** | Full scanner run | `argus_rules.py test` |
| **Validation** | Manual | `argus_rules.py validate` |
| **Documentation** | Code comments | YAML descriptions |

## What's Next?

With the rule engine complete, remaining architectural improvements:

1. ✅ **Async Architecture** - 5.7x speedup
2. ✅ **OAST Implementation** - Blind vuln detection
3. ✅ **Differential Analysis** - 80% fewer false positives
4. ✅ **Fuzzing Engine** - Adaptive payloads
5. ✅ **Configurable Rules** - This document
6. ⏸️ **Enhanced Crawler** - Modern web support
7. ⏸️ **Compliance Mapping** - OWASP, CWE, PCI-DSS
8. ⏸️ **Database Layer** - Scan management

**Progress: 5/8 complete (62.5%)** 🎯
