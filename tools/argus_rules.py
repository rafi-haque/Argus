#!/usr/bin/env python3
"""Argus Rule Manager - CLI tool for managing scanner rules.

This tool helps users create, view, edit, and validate rule files.
"""
import argparse
import sys
from pathlib import Path
from argus.modules.rule_engine import RuleEngine, create_default_rules_file


def cmd_export(args):
    """Export current rules to a file."""
    engine = RuleEngine()
    engine.export_rules(args.output, format=args.format)
    print(f"✅ Rules exported to: {args.output}")


def cmd_validate(args):
    """Validate a rules file."""
    try:
        engine = RuleEngine(args.rules_file)
        enabled_rules = engine.list_rules(enabled_only=True)
        all_rules = engine.list_rules(enabled_only=False)
        
        print(f"✅ Rules file is valid: {args.rules_file}")
        print(f"   Total rules: {len(all_rules)}")
        print(f"   Enabled rules: {len(enabled_rules)}")
        print(f"   Disabled rules: {len(all_rules) - len(enabled_rules)}")
        
        # Show rule summary by weight
        print("\n📊 Rule Distribution:")
        weight_counts = {}
        for rule in enabled_rules:
            weight_range = f"{rule.weight // 10 * 10}-{rule.weight // 10 * 10 + 9}"
            weight_counts[weight_range] = weight_counts.get(weight_range, 0) + 1
        
        for weight_range in sorted(weight_counts.keys(), reverse=True):
            count = weight_counts[weight_range]
            bar = '█' * (count * 2)
            print(f"   {weight_range}: {bar} ({count})")
        
    except Exception as e:
        print(f"❌ Invalid rules file: {e}")
        sys.exit(1)


def cmd_list(args):
    """List all rules."""
    try:
        engine = RuleEngine(args.rules_file) if args.rules_file else RuleEngine()
        rules = engine.list_rules(
            tag=args.tag,
            enabled_only=not args.all
        )
        
        if not rules:
            print("No rules found.")
            return
        
        print(f"📋 Found {len(rules)} rules:\n")
        
        for rule in rules:
            status = "✅" if rule.enabled else "❌"
            tags_str = f" [{', '.join(rule.tags)}]" if rule.tags else ""
            print(f"{status} [{rule.weight:3d}] {rule.name}{tags_str}")
            
            if args.verbose:
                print(f"    Description: {rule.description}")
                print(f"    Modules: {', '.join(rule.modules)}")
                print(f"    Condition: {rule.condition}")
                print()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_test(args):
    """Test rules against a parameter."""
    try:
        engine = RuleEngine(args.rules_file) if args.rules_file else RuleEngine()
        
        # Build parameter dict
        parameter = {
            'name': args.param_name,
            'value': args.param_value or '',
            'location': args.location or 'query'
        }
        
        # Build context dict
        context = {
            'url': args.url,
            'method': args.method,
            'all_params': [parameter]
        }
        
        print(f"🔍 Testing rules for parameter: {args.param_name}")
        print(f"   URL: {args.url}")
        print(f"   Method: {args.method}\n")
        
        # Find matching rules
        matched_rules = []
        for rule in engine.rules:
            if rule.matches(parameter, context):
                matched_rules.append(rule)
        
        if not matched_rules:
            print("No rules matched this parameter.")
            return
        
        print(f"✅ {len(matched_rules)} rules matched:\n")
        
        for rule in matched_rules:
            print(f"  [{rule.weight:3d}] {rule.name}")
            print(f"       Modules: {', '.join(rule.modules)}")
            if args.verbose:
                print(f"       Description: {rule.description}")
            print()
        
        # Show prioritization
        available_modules = list(set(m for r in matched_rules for m in r.modules))
        prioritized = engine.prioritize_modules(parameter, context, available_modules)
        
        print("📊 Module Priority Order:")
        for i, module in enumerate(prioritized, 1):
            print(f"   {i}. {module}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def cmd_create(args):
    """Create a default rules file."""
    if Path(args.output).exists() and not args.force:
        print(f"❌ File already exists: {args.output}")
        print("   Use --force to overwrite")
        sys.exit(1)
    
    create_default_rules_file(args.output)


def cmd_stats(args):
    """Show statistics about rules."""
    try:
        engine = RuleEngine(args.rules_file) if args.rules_file else RuleEngine()
        rules = engine.list_rules(enabled_only=False)
        enabled = [r for r in rules if r.enabled]
        
        # Calculate stats
        total_modules = len(set(m for r in rules for m in r.modules))
        avg_weight = sum(r.weight for r in enabled) / len(enabled) if enabled else 0
        all_tags = set(t for r in rules for t in r.tags)
        
        print("📊 Rule Statistics:")
        print(f"   Total rules: {len(rules)}")
        print(f"   Enabled: {len(enabled)}")
        print(f"   Disabled: {len(rules) - len(enabled)}")
        print(f"   Unique modules referenced: {total_modules}")
        print(f"   Average weight: {avg_weight:.1f}")
        print(f"   Unique tags: {len(all_tags)}")
        
        if args.verbose:
            print(f"\n🏷️  Tags: {', '.join(sorted(all_tags))}")
            
            # Module frequency
            module_counts = {}
            for rule in enabled:
                for module in rule.modules:
                    module_counts[module] = module_counts.get(module, 0) + 1
            
            print("\n🔧 Most Referenced Modules:")
            for module, count in sorted(module_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"   {module}: {count} rules")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Argus Rule Manager - Manage scanner prioritization rules',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export default rules to file')
    export_parser.add_argument('output', help='Output file path')
    export_parser.add_argument('--format', choices=['yaml', 'json'], default='yaml',
                              help='Output format (default: yaml)')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate rules file')
    validate_parser.add_argument('rules_file', help='Rules file to validate')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all rules')
    list_parser.add_argument('--rules-file', help='Custom rules file')
    list_parser.add_argument('--tag', help='Filter by tag')
    list_parser.add_argument('--all', action='store_true', help='Include disabled rules')
    list_parser.add_argument('-v', '--verbose', action='store_true', help='Show details')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test rules against a parameter')
    test_parser.add_argument('param_name', help='Parameter name')
    test_parser.add_argument('--url', default='http://example.com', help='URL')
    test_parser.add_argument('--method', default='GET', help='HTTP method')
    test_parser.add_argument('--param-value', help='Parameter value')
    test_parser.add_argument('--location', choices=['query', 'body', 'cookie', 'header'],
                           help='Parameter location')
    test_parser.add_argument('--rules-file', help='Custom rules file')
    test_parser.add_argument('-v', '--verbose', action='store_true', help='Show details')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create default rules file')
    create_parser.add_argument('output', help='Output file path')
    create_parser.add_argument('--force', action='store_true', help='Overwrite existing file')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show rule statistics')
    stats_parser.add_argument('--rules-file', help='Custom rules file')
    stats_parser.add_argument('-v', '--verbose', action='store_true', help='Show details')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    commands = {
        'export': cmd_export,
        'validate': cmd_validate,
        'list': cmd_list,
        'test': cmd_test,
        'create': cmd_create,
        'stats': cmd_stats
    }
    
    commands[args.command](args)


if __name__ == '__main__':
    main()
