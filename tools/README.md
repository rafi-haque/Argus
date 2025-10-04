# Argus Tools

Utility scripts and tools for working with Argus scanner.

## 📋 Available Tools

### 1. argus_db.py - Database Manager

Manage and query scan results stored in the database.

**Usage:**
```bash
python tools/argus_db.py --db <database_file> <command> [options]
```

**Commands:**

| Command | Description | Example |
|---------|-------------|---------|
| `list` | List all scans | `python tools/argus_db.py --db scans.db list` |
| `show <id>` | Show detailed scan results | `python tools/argus_db.py --db scans.db show 1` |
| `trend` | Show vulnerability trends | `python tools/argus_db.py --db scans.db trend --days 30` |
| `compare <id1> <id2>` | Compare two scans | `python tools/argus_db.py --db scans.db compare 1 2` |
| `export <id>` | Export scan to JSON | `python tools/argus_db.py --db scans.db export 1 -o scan.json` |
| `delete <id>` | Delete a scan | `python tools/argus_db.py --db scans.db delete 5` |
| `schedule add` | Add scheduled scan | `python tools/argus_db.py --db scans.db schedule add --url https://example.com --cron "0 2 * * *"` |
| `schedule list` | List scheduled scans | `python tools/argus_db.py --db scans.db schedule list` |
| `schedule show <id>` | Show schedule details | `python tools/argus_db.py --db scans.db schedule show 1` |
| `schedule pause <id>` | Pause scheduled scan | `python tools/argus_db.py --db scans.db schedule pause 1` |
| `schedule resume <id>` | Resume scheduled scan | `python tools/argus_db.py --db scans.db schedule resume 1` |
| `schedule delete <id>` | Delete scheduled scan | `python tools/argus_db.py --db scans.db schedule delete 1` |
| `init` | Initialize database schema | `python tools/argus_db.py --db scans.db init` |

**Examples:**

```bash
# List all scans with summary
python tools/argus_db.py --db scans.db list

# Show detailed results from scan #1
python tools/argus_db.py --db scans.db show 1

# Compare scans to see what's new/fixed
python tools/argus_db.py --db scans.db compare 1 2

# View vulnerability trends over last 30 days
python tools/argus_db.py --db scans.db trend --days 30

# Schedule daily scan at 2 AM
python tools/argus_db.py --db scans.db schedule add \
  --url https://example.com \
  --cron "0 2 * * *" \
  --policy standard
```

---

### 2. argus_compliance.py - Compliance Reporter

Generate compliance reports mapping vulnerabilities to security frameworks.

**Usage:**
```bash
python tools/argus_compliance.py --db <database_file> --scan-id <id> [options]
```

**Options:**
- `--format <format>` - Output format: terminal, json, html, markdown (default: terminal)
- `--output <file>` - Output file (default: stdout for terminal)
- `--framework <name>` - Filter by framework: owasp, cwe, pci-dss, hipaa

**Examples:**

```bash
# Generate terminal report
python tools/argus_compliance.py --db scans.db --scan-id 1

# Generate HTML report
python tools/argus_compliance.py --db scans.db --scan-id 1 \
  --format html --output report.html

# Generate JSON report for specific framework
python tools/argus_compliance.py --db scans.db --scan-id 1 \
  --format json --framework owasp --output owasp_report.json

# Generate Markdown report
python tools/argus_compliance.py --db scans.db --scan-id 1 \
  --format markdown --output report.md
```

---

### 3. argus_rules.py - Rule Engine Tester

Test and validate prioritization rules.

**Usage:**
```bash
python tools/argus_rules.py [options]
```

**Options:**
- `--rules <file>` - Rules file to test (default: argus/config/rules.yaml)
- `--test <file>` - Test cases file
- `--verbose` - Show detailed rule matching

**Examples:**

```bash
# Test default rules
python tools/argus_rules.py

# Test custom rules file
python tools/argus_rules.py --rules custom_rules.yaml

# Run with test cases
python tools/argus_rules.py --test test_cases.yaml --verbose
```

---

### 4. demo_database.py - Database Demo

Demonstrate database features with sample data.

**Usage:**
```bash
python tools/demo_database.py
```

**Features:**
- Creates sample scan data
- Demonstrates storage and retrieval
- Shows trend analysis
- Tests scan comparison
- Examples of scheduled scans

---

### 5. demo_compliance.py - Compliance Demo

Demonstrate compliance reporting features.

**Usage:**
```bash
python tools/demo_compliance.py
```

**Generates:**
- Sample scan with findings
- OWASP Top 10 mapping
- CWE classification
- PCI-DSS requirements
- HIPAA controls
- Reports in all formats (terminal, JSON, HTML, Markdown)

---

### 6. demo_enhanced_crawler.py - Crawler Demo

Demonstrate enhanced crawler capabilities.

**Usage:**
```bash
python tools/demo_enhanced_crawler.py <url>
```

**Features:**
- Deep site mapping
- Form discovery
- JavaScript handling
- Link extraction
- Endpoint categorization

**Example:**
```bash
python tools/demo_enhanced_crawler.py https://example.com
```

---

### 7. demo_rule_engine.py - Rule Engine Demo

Demonstrate context-aware module prioritization.

**Usage:**
```bash
python tools/demo_rule_engine.py
```

**Features:**
- Shows rule matching logic
- Demonstrates context-based prioritization
- Tests various parameter scenarios
- Displays module ordering

---

### 8. benchmark_async.py - Performance Benchmark

Benchmark async vs sync performance.

**Usage:**
```bash
python tools/benchmark_async.py [--requests N] [--concurrent N]
```

**Options:**
- `--requests N` - Number of requests to test (default: 100)
- `--concurrent N` - Concurrent requests (default: 10)

**Example:**
```bash
python tools/benchmark_async.py --requests 500 --concurrent 20
```

---

### 9. convert_to_async.py - Migration Tool

Convert synchronous modules to async (development tool).

**Usage:**
```bash
python tools/convert_to_async.py <input_file> [--output <output_file>]
```

**Example:**
```bash
python tools/convert_to_async.py old_module.py --output new_module.py
```

---

### 10. scan.sh - Quick Scan Script

Bash script for quick scanning (Linux/macOS).

**Usage:**
```bash
./tools/scan.sh <url> [policy]
```

**Example:**
```bash
./tools/scan.sh https://example.com quick
./tools/scan.sh https://example.com standard
```

---

## 🔧 Development Tools

### Running All Demos

```bash
# Run all demonstration scripts
python tools/demo_database.py
python tools/demo_compliance.py
python tools/demo_rule_engine.py
python tools/demo_enhanced_crawler.py https://example.com
```

### Testing Database Features

```bash
# Initialize database
python tools/argus_db.py --db test.db init

# Run a scan with database storage
python -m argus.main --url https://example.com --db test.db

# View results
python tools/argus_db.py --db test.db list
python tools/argus_db.py --db test.db show 1
```

### Creating Scheduled Scans

```bash
# Add daily scan
python tools/argus_db.py --db scans.db schedule add \
  --url https://example.com \
  --cron "0 2 * * *" \
  --policy standard

# Add weekly scan
python tools/argus_db.py --db scans.db schedule add \
  --url https://example.com \
  --interval weekly \
  --policy comprehensive
```

## 📚 Additional Resources

- [Database Guide](../docs/guides/DATABASE_GUIDE.md)
- [Compliance Guide](../docs/guides/COMPLIANCE_GUIDE.md)
- [Rule Engine Guide](../docs/guides/RULE_ENGINE_GUIDE.md)
- [Quick Reference](../docs/guides/QUICK_REFERENCE.md)

---

For more information, see the main [README](../README.md).
