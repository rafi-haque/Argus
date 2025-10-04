#!/usr/bin/env python3
"""Rule Engine Demo - Shows rule engine in action.

Demonstrates:
1. Loading rules from YAML
2. Evaluating rules against parameters
3. Module prioritization
4. Different condition types
"""
import sys
from pathlib import Path

# Add argus to path
sys.path.insert(0, str(Path(__file__).parent))

from argus.modules.rule_engine import RuleEngine


def print_header(text):
    """Print formatted header."""
    print(f"\n{'='*70}")
    print(f"  {text}")
    print('='*70)


def test_parameter(engine, param_name, url, method='GET', verbose=False):
    """Test a parameter against rules."""
    print(f"\n🔍 Testing: {param_name}")
    print(f"   URL: {url}")
    print(f"   Method: {method}")
    
    # Build parameter dict
    parameter = {
        'name': param_name,
        'value': 'test_value',
        'location': 'query'
    }
    
    # Build context dict
    context = {
        'url': url,
        'method': method,
        'all_params': [parameter]
    }
    
    # Find matching rules
    matched_rules = []
    for rule in engine.rules:
        if rule.enabled and rule.matches(parameter, context):
            matched_rules.append(rule)
    
    if matched_rules:
        print(f"\n   ✅ {len(matched_rules)} rules matched:")
        for rule in sorted(matched_rules, key=lambda r: r.weight, reverse=True):
            print(f"      [{rule.weight:3d}] {rule.name}")
            if verbose:
                print(f"           → Modules: {', '.join(rule.modules)}")
    else:
        print("   ❌ No rules matched")
    
    # Show prioritization
    available_modules = ['sqli', 'xss', 'csrf', 'open_redirect', 'ssrf', 
                        'path_traversal', 'command_injection', 'idor', 
                        'lfi_rfi', 'insecure_headers', 'cors', 'api_vulnerabilities']
    
    prioritized = engine.prioritize_modules(parameter, context, available_modules)
    
    print("\n   📊 Module Priority Order (top 5):")
    for i, module in enumerate(prioritized[:5], 1):
        print(f"      {i}. {module}")


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║            Argus Rule Engine - Interactive Demo                  ║
║                                                                   ║
║  Demonstrates intelligent module prioritization using YAML rules ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Load default rules
    print("📋 Loading default rules...")
    rules_file = Path(__file__).parent / 'argus' / 'config' / 'rules.yaml'
    
    if rules_file.exists():
        engine = RuleEngine(str(rules_file))
        print(f"   ✅ Loaded from: {rules_file}")
    else:
        engine = RuleEngine()
        print("   ✅ Loaded built-in default rules")
    
    enabled_rules = engine.list_rules(enabled_only=True)
    all_rules = engine.list_rules(enabled_only=False)
    
    print(f"   Total rules: {len(all_rules)}")
    print(f"   Enabled: {len(enabled_rules)}")
    print(f"   Disabled: {len(all_rules) - len(enabled_rules)}")
    
    # Show rule distribution
    print_header("Rule Weight Distribution")
    weight_counts = {}
    for rule in enabled_rules:
        weight_range = f"{rule.weight // 10 * 10}-{rule.weight // 10 * 10 + 9}"
        weight_counts[weight_range] = weight_counts.get(weight_range, 0) + 1
    
    for weight_range in sorted(weight_counts.keys(), reverse=True):
        count = weight_counts[weight_range]
        bar = '█' * (count * 3)
        print(f"   {weight_range}: {bar} ({count} rules)")
    
    # Test different scenarios
    print_header("Test Scenario 1: URL Parameter")
    test_parameter(engine, 'redirect_url', 'http://example.com/login', 'GET', verbose=True)
    
    print_header("Test Scenario 2: File Parameter")
    test_parameter(engine, 'file_path', 'http://example.com/download', 'GET', verbose=True)
    
    print_header("Test Scenario 3: Command Parameter")
    test_parameter(engine, 'exec_command', 'http://example.com/admin/shell', 'POST', verbose=True)
    
    print_header("Test Scenario 4: ID Parameter")
    test_parameter(engine, 'user_id', 'http://example.com/api/v1/users', 'GET', verbose=True)
    
    print_header("Test Scenario 5: Search Parameter")
    test_parameter(engine, 'search_query', 'http://example.com/search', 'GET', verbose=True)
    
    print_header("Test Scenario 6: API Endpoint")
    test_parameter(engine, 'data', 'http://api.example.com/v1/orders', 'POST', verbose=True)
    
    print_header("Test Scenario 7: Admin Panel")
    test_parameter(engine, 'action', 'http://example.com/admin/users', 'POST', verbose=True)
    
    print_header("Test Scenario 8: Generic Parameter (Fallback)")
    test_parameter(engine, 'foo', 'http://example.com/page', 'GET', verbose=True)
    
    # Show top rules
    print_header("Top 10 Highest Priority Rules")
    top_rules = sorted(enabled_rules, key=lambda r: r.weight, reverse=True)[:10]
    
    for i, rule in enumerate(top_rules, 1):
        tags = f" [{', '.join(rule.tags)}]" if rule.tags else ""
        print(f"   {i}. [{rule.weight:3d}] {rule.name}{tags}")
        print(f"      Modules: {', '.join(rule.modules)}")
    
    # Summary
    print_header("Summary")
    print("""
   ✅ Rule engine loaded successfully
   ✅ All test scenarios completed
   ✅ Intelligent prioritization demonstrated
   
   Key Benefits:
   • No hardcoded if/elif logic
   • User-customizable via YAML
   • Weighted scoring system
   • Context-aware prioritization
   • Complex condition support
   
   Next Steps:
   1. Customize rules:  python argus_rules.py create my_rules.yaml
   2. Test rules:       python argus_rules.py test <param_name>
   3. Validate rules:   python argus_rules.py validate my_rules.yaml
   4. Use in scan:      python argus/main.py --url <URL> --rules my_rules.yaml
    """)
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    main()
