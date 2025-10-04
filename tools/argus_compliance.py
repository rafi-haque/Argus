#!/usr/bin/env python3
"""Compliance report generator for Argus scan results.

Usage:
    python argus_compliance.py --json scan_results.json --output compliance_report
    python argus_compliance.py --json scan_results.json --format html --output report.html
"""

import argparse
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from argus.compliance.mappings import ComplianceMapper
from argus.compliance.reporting import ComplianceReportGenerator


def load_scan_results(json_file: str) -> dict:
    """Load scan results from JSON file.
    
    Args:
        json_file: Path to JSON scan results
    
    Returns:
        dict: Scan results
    """
    with open(json_file) as f:
        return json.load(f)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Generate compliance reports from Argus scan results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all formats
  python argus_compliance.py --json scan.json --output compliance --format json html markdown
  
  # Generate HTML report only
  python argus_compliance.py --json scan.json --output report.html --format html
  
  # Export compliance mappings
  python argus_compliance.py --export-mappings ./compliance_mappings/
  
  # Validate compliance configuration
  python argus_compliance.py --validate
        """
    )
    
    parser.add_argument(
        '--json',
        help='Path to JSON scan results file',
        metavar='FILE'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path (without extension for multiple formats)',
        metavar='PATH'
    )
    
    parser.add_argument(
        '--format',
        nargs='+',
        choices=['json', 'yaml', 'html', 'markdown'],
        default=['json'],
        help='Output format(s) (default: json)'
    )
    
    parser.add_argument(
        '--export-mappings',
        metavar='DIR',
        help='Export compliance mappings to directory'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate compliance mappings'
    )
    
    parser.add_argument(
        '--list-standards',
        action='store_true',
        help='List supported compliance standards'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # List standards
    if args.list_standards:
        print("\n📋 Supported Compliance Standards:")
        print("  • OWASP Top 10 2021")
        print("  • CWE (Common Weakness Enumeration)")
        print("  • PCI-DSS v4.0 (Payment Card Industry Data Security Standard)")
        print("  • HIPAA Security Rule (Health Insurance Portability and Accountability Act)")
        print("\nFor more information, visit:")
        print("  • https://owasp.org/Top10/")
        print("  • https://cwe.mitre.org/")
        print("  • https://www.pcisecuritystandards.org/")
        print("  • https://www.hhs.gov/hipaa/")
        return 0
    
    # Export mappings
    if args.export_mappings:
        print(f"📤 Exporting compliance mappings to {args.export_mappings}...")
        mapper = ComplianceMapper()
        mapper.export_mappings(args.export_mappings)
        print(f"✅ Mappings exported successfully!")
        print(f"   • owasp_top10.yaml")
        print(f"   • cwe_mappings.yaml")
        print(f"   • pci_dss.yaml")
        print(f"   • hipaa.yaml")
        return 0
    
    # Validate mappings
    if args.validate:
        print("🔍 Validating compliance mappings...")
        try:
            mapper = ComplianceMapper()
            
            # Check OWASP
            owasp_count = len(mapper.owasp_mappings)
            print(f"✅ OWASP Top 10: {owasp_count} vulnerability types mapped")
            
            # Check CWE
            cwe_count = len(mapper.cwe_mappings)
            total_cwes = sum(len(v['cwe_ids']) for v in mapper.cwe_mappings.values())
            print(f"✅ CWE: {cwe_count} vulnerability types, {total_cwes} CWE IDs")
            
            # Check PCI-DSS
            pci_count = len(mapper.pci_mappings)
            total_reqs = sum(len(v['requirements']) for v in mapper.pci_mappings.values())
            print(f"✅ PCI-DSS v4.0: {pci_count} vulnerability types, {total_reqs} requirements")
            
            # Check HIPAA
            hipaa_count = len(mapper.hipaa_mappings)
            total_controls = sum(len(v['controls']) for v in mapper.hipaa_mappings.values())
            print(f"✅ HIPAA: {hipaa_count} vulnerability types, {total_controls} controls")
            
            print("\n✅ All compliance mappings validated successfully!")
            return 0
        except Exception as e:
            print(f"\n❌ Validation failed: {e}")
            return 1
    
    # Generate compliance report
    if not args.json:
        parser.error("--json is required when generating reports")
    
    if not args.output:
        parser.error("--output is required when generating reports")
    
    try:
        # Load scan results
        if args.verbose:
            print(f"📂 Loading scan results from {args.json}...")
        
        scan_data = load_scan_results(args.json)
        findings = scan_data.get('findings', [])
        
        if not findings:
            print("⚠️  No findings in scan results. Nothing to report.")
            return 0
        
        if args.verbose:
            print(f"✅ Loaded {len(findings)} findings")
        
        # Generate compliance report
        if args.verbose:
            print(f"📊 Generating compliance report...")
        
        generator = ComplianceReportGenerator()
        report = generator.generate_compliance_report(
            findings,
            output_path=args.output,
            formats=args.format
        )
        
        # Display summary
        print("\n" + "="*70)
        print("📋 COMPLIANCE REPORT GENERATED")
        print("="*70)
        
        exec_summary = report['executive_summary']
        print(f"\n🎯 Overall Status: {exec_summary['overall_status']}")
        print(f"🔢 Risk Score: {exec_summary['risk_score']}/100")
        
        print(f"\n📊 Findings by Severity:")
        for severity, count in exec_summary['severity_breakdown'].items():
            if count > 0:
                print(f"   • {severity}: {count}")
        
        compliance = report['compliance_summary']
        print(f"\n📋 Standards Impacted:")
        print(f"   • OWASP Top 10: {compliance['owasp_top10']['count']} categories")
        print(f"   • CWE: {compliance['cwe']['count']} weaknesses")
        print(f"   • PCI-DSS: {compliance['pci_dss']['count']} requirements")
        print(f"   • HIPAA: {compliance['hipaa']['count']} controls")
        
        print(f"\n💾 Report Files:")
        for fmt in args.format:
            ext = {'json': '.json', 'yaml': '.yaml', 'html': '.html', 'markdown': '.md'}
            output_file = Path(args.output).with_suffix(ext[fmt])
            print(f"   • {output_file}")
        
        print("\n✅ Compliance report generation complete!")
        
        return 0
        
    except FileNotFoundError:
        print(f"❌ Error: File not found: {args.json}")
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {args.json}: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
