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
    
    # Build configuration
    config = {
        'seed_url': args.url,
        'auth': None,
        'scope': {
            'include_patterns': args.include_pattern or [],
            'exclude_patterns': args.exclude_pattern or []
        },
        'performance': {
            'max_concurrent': args.max_concurrent,
            'request_delay': args.request_delay,
            'timeout': 10
        },
        'verbose': args.verbose
    }
    
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
    print(f"⚙️  Max Concurrent: {args.max_concurrent}")
    print(f"⏱️  Request Delay: {args.request_delay}s")
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
        from argus.modules.orchestrator import ScannerOrchestrator
        from argus.modules.reporting import CLIReporter
        
        # Initialize attack modules
        modules = [
            InsecureHeadersModule(config),
            SQLiModule(config),
            XSSModule(config),
            CSRFModule(config),
            PathTraversalModule(config),
            CommandInjectionModule(config),
            CORSModule(config),
            OpenRedirectModule(config),
        ]
        
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
