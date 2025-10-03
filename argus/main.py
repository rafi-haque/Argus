#!/usr/bin/env python3
"""Argus Web Vulnerability Scanner - Main CLI Entry Point."""
import argparse
import sys
from typing import Optional


def parse_arguments():
    """Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Argus - Context-aware web vulnerability scanner',
        epilog='Remember: Only scan systems you have permission to test!'
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to scan (e.g., http://localhost:3000)'
    )
    
    parser.add_argument(
        '--policy',
        choices=['quick', 'standard', 'full', 'api', 'owasp-top10', 'custom'],
        default='standard',
        help='Scan policy to use (default: standard)'
    )
    
    parser.add_argument(
        '--modules',
        help='Comma-separated list of modules to enable (for custom policy)'
    )
    
    parser.add_argument(
        '--auth-header',
        help='Authentication header (e.g., "Authorization: Bearer token")'
    )
    
    parser.add_argument(
        '--include-pattern',
        action='append',
        help='Regex pattern for URLs to include in scope'
    )
    
    parser.add_argument(
        '--exclude-pattern',
        action='append',
        help='Regex pattern for URLs to exclude from scope'
    )
    
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=5,
        help='Maximum concurrent requests (default: 5)'
    )
    
    parser.add_argument(
        '--request-delay',
        type=float,
        default=0.1,
        help='Delay between requests in seconds (default: 0.1)'
    )
    
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Output results to JSON file'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Argus 1.0.0'
    )
    
    return parser.parse_args()


def show_disclaimer():
    """Display ethical use disclaimer."""
    disclaimer = """
╔═══════════════════════════════════════════════════════════════════════╗
║                 ⚠️  ARGUS WEB VULNERABILITY SCANNER ⚠️                 ║
║                                                                       ║
║  ETHICAL USE ONLY - You must have explicit permission to scan        ║
║  any system. Unauthorized scanning is ILLEGAL.                       ║
║                                                                       ║
║  By using this tool, you agree to:                                   ║
║  • Only scan systems you own or have written authorization           ║
║  • Comply with all applicable laws and regulations                   ║
║  • Take full responsibility for your actions                         ║
║                                                                       ║
║  Context-aware scanning • Modular architecture • Developer-first     ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(disclaimer)


def main():
    """Main entry point for Argus scanner."""
    # Show disclaimer
    show_disclaimer()
    
    # Parse arguments
    args = parse_arguments()
    
    # Load scan policy
    from argus.config.scan_policies import get_policy
    
    if args.policy == 'custom' and args.modules:
        policy = get_policy('custom', modules=args.modules.split(','))
    else:
        policy = get_policy(args.policy)
    
    policy_config = policy.to_dict()
    
    # Build configuration
    config = {
        'seed_url': args.url,
        'auth': None,
        'scope': policy_config['scope'],
        'performance': policy_config['performance'],
        'verbose': args.verbose,
        'use_browser_validation': True,  # Enable XSS browser validation
    }
    
    # Override with command-line arguments if provided
    if args.max_concurrent:
        config['performance']['max_concurrent'] = args.max_concurrent
    if args.request_delay:
        config['performance']['request_delay'] = args.request_delay
    if args.include_pattern:
        config['scope']['include_patterns'] = args.include_pattern
    if args.exclude_pattern:
        config['scope']['exclude_patterns'] = args.exclude_pattern
    
    # Parse auth header if provided
    if args.auth_header:
        if ':' in args.auth_header:
            header_name, header_value = args.auth_header.split(':', 1)
            config['auth'] = {
                'type': 'header',
                'name': header_name.strip(),
                'value': header_value.strip()
            }
    
    print(f"\n🎯 Target: {args.url}")
    print(f"📋 Policy: {policy.name} - {policy.description}")
    print(f"🔧 Modules: {', '.join(policy_config['modules'])}")
    print(f"⚙️  Max Concurrent: {config['performance']['max_concurrent']}")
    print(f"⏱️  Request Delay: {config['performance']['request_delay']}s")
    print("\n🔍 Starting scan...\n")
    
    try:
        # Import modules here to allow --version and --help to work without dependencies
        from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
        from argus.modules.attack_modules.sqli import SQLiModule
        from argus.modules.attack_modules.xss import XSSModule
        from argus.modules.attack_modules.csrf import CSRFModule
        from argus.modules.attack_modules.path_traversal import PathTraversalModule
        from argus.modules.attack_modules.command_injection import CommandInjectionModule
        from argus.modules.attack_modules.cors import CORSModule
        from argus.modules.attack_modules.open_redirect import OpenRedirectModule
        from argus.modules.attack_modules.ssrf import SSRFModule
        from argus.modules.attack_modules.lfi_rfi import LFIRFIModule
        from argus.modules.attack_modules.insecure_deserialization import InsecureDeserializationModule
        from argus.modules.attack_modules.api_vulnerabilities import APIVulnerabilitiesModule
        from argus.modules.orchestrator import ScannerOrchestrator
        from argus.modules.reporting import CLIReporter
        
        # All available modules
        all_modules = {
            'insecure_headers': InsecureHeadersModule(config),
            'sqli': SQLiModule(config),
            'xss': XSSModule(config),
            'csrf': CSRFModule(config),
            'path_traversal': PathTraversalModule(config),
            'command_injection': CommandInjectionModule(config),
            'cors': CORSModule(config),
            'open_redirect': OpenRedirectModule(config),
            'ssrf': SSRFModule(config),
            'lfi_rfi': LFIRFIModule(config),
            'insecure_deserialization': InsecureDeserializationModule(config),
            'api_vulnerabilities': APIVulnerabilitiesModule(config),
        }
        
        # Filter modules based on policy
        enabled_modules = policy_config['modules']
        modules = [all_modules[name] for name in enabled_modules if name in all_modules]
        
        if not modules:
            print("❌ No valid modules enabled in policy")
            return 1
        
        # Initialize orchestrator and reporter
        orchestrator = ScannerOrchestrator(config, modules)
        reporter = CLIReporter(config)
        
        # Run full scan
        result = orchestrator.run_scan(args.url)
        
        # Report findings
        reporter.generate_report(
            result['findings'],
            result['site_map'],
            result['stats']
        )
        
        # JSON output if requested
        if args.json:
            from argus.modules.reporting import JSONReporter
            json_reporter = JSONReporter(config)
            json_reporter.generate_report(
                result['findings'],
                result['site_map'],
                result['stats'],
                args.json
            )
            print(f"\n💾 JSON report saved to: {args.json}")
        
        # Exit code based on findings
        if result['findings']:
            return 1  # Vulnerabilities found
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
