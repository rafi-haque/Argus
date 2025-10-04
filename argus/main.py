#!/usr/bin/env python3
"""Argus Web Vulnerability Scanner - Main CLI Entry Point.

ASYNC-ONLY ARCHITECTURE
Uses asyncio for high-performance concurrent scanning.
"""
import argparse
import sys
import asyncio
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
    
    parser.add_argument(
        '--db',
        metavar='FILE',
        help='Database file for storing scan results (e.g., argus.db)'
    )
    
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='Disable database storage'
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
    
    # Run async main
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


async def async_main(args):
    """Async main function that runs the scan."""
async def async_main(args):
    """Async main function that runs the scan."""
    
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
        'timeout': 10,
        'max_connections': 100,
        'max_keepalive_connections': 50,
        'rate_limit_per_second': 20,
    }
    
    # Override with command-line arguments if provided
    if args.max_concurrent:
        config['max_connections'] = args.max_concurrent
    if args.request_delay and args.request_delay > 0:
        config['rate_limit_per_second'] = int(1.0 / args.request_delay)
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
    print(f"⚙️  Max Connections: {config['max_connections']}")
    print(f"⚡ Rate Limit: {config['rate_limit_per_second']} req/s")
    print("\n🔍 Starting scan...\n")
    
    # Initialize database if requested
    db = None
    if args.db and not args.no_db:
        try:
            from argus.database import ScanDatabase
            db = ScanDatabase(f'sqlite:///{args.db}')
            print(f"💾 Database: {args.db}\n")
        except Exception as e:
            print(f"⚠️  Database error: {e}")
            print("   Continuing without database storage\n")
    
    # Import modules
    from argus.modules.attack_modules.async_sqli import AsyncSQLiModule
    # Import all async modules (no wrappers needed!)
    from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule
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
    
    # All available modules (all native async now!)
    all_modules = {
        'sqli': AsyncSQLiModule(config),
        'insecure_headers': InsecureHeadersModule(config),
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
    
    # Run full scan (now async!)
    result = await orchestrator.run_scan(args.url)
    
    # Report findings
    reporter.generate_report(
        result['findings'],
        result['site_map'],
        result['stats']
    )
    
    # Store in database if enabled
    if db:
        try:
            # Normalize severity values to lowercase for database
            normalized_findings = []
            for finding in result['findings']:
                normalized_finding = finding.copy()
                if 'severity' in normalized_finding:
                    normalized_finding['severity'] = normalized_finding['severity'].lower()
                normalized_findings.append(normalized_finding)
            
            scan_id = db.store_scan(
                target_url=args.url,
                findings=normalized_findings,
                stats=result['stats'],
                config=config,
                status='completed',
                notes=f"Policy: {args.policy}"
            )
            print(f"\n💾 Scan #{scan_id} stored in database")
        except Exception as e:
            print(f"\n⚠️  Failed to store scan: {e}")
        finally:
            db.close()
    
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


if __name__ == '__main__':
    sys.exit(main())
