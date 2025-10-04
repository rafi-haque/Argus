#!/usr/bin/env python3
"""Demo script for Argus compliance mapping system.

Demonstrates:
1. Finding enrichment with compliance metadata
2. Compliance summary generation
3. Report generation in multiple formats
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from argus.compliance.mappings import ComplianceMapper
from argus.compliance.reporting import ComplianceReportGenerator, generate_compliance_cli_report


def demo_basic_mapping():
    """Demonstrate basic compliance mapping."""
    print("\n" + "="*70)
    print("DEMO 1: Basic Compliance Mapping")
    print("="*70 + "\n")
    
    # Sample findings
    findings = [
        {
            'name': 'SQL Injection',
            'module': 'sqli',
            'severity': 'Critical',
            'url': 'http://example.com/search',
            'parameter': 'q',
            'payload': "' OR '1'='1",
            'evidence': 'SQL error: syntax error near OR',
            'recommendation': 'Use parameterized queries'
        },
        {
            'name': 'Cross-Site Scripting (XSS) - Reflected',
            'module': 'xss',
            'severity': 'High',
            'url': 'http://example.com/comment',
            'parameter': 'msg',
            'payload': '<script>alert(1)</script>',
            'evidence': 'Script executed in response',
            'recommendation': 'Implement output encoding'
        },
        {
            'name': 'Broken Object Level Authorization (BOLA/IDOR)',
            'module': 'api_vulnerabilities',
            'severity': 'High',
            'url': 'http://example.com/api/users/123',
            'parameter': 'user_id',
            'payload': '456',
            'evidence': 'Accessed other user data',
            'recommendation': 'Implement proper authorization checks'
        }
    ]
    
    # Initialize mapper
    mapper = ComplianceMapper()
    
    # Enrich findings
    enriched = mapper.enrich_findings(findings)
    
    # Display enriched findings
    for finding in enriched:
        print(f"🔍 {finding['name']}")
        print(f"   Severity: {finding['severity']}")
        
        compliance = finding['compliance']
        owasp = compliance['owasp']
        
        print(f"\n   📋 Compliance Mappings:")
        print(f"      OWASP: {owasp['id']} - {owasp['category']}")
        print(f"      CWE: {', '.join([f'CWE-{cwe}' for cwe in compliance['cwe_ids']])}")
        print(f"      PCI-DSS: {', '.join(compliance['pci_dss'][:3])}")
        print(f"      HIPAA: {', '.join(compliance['hipaa'][:2])}")
        print()


def demo_compliance_summary():
    """Demonstrate compliance summary generation."""
    print("\n" + "="*70)
    print("DEMO 2: Compliance Summary")
    print("="*70 + "\n")
    
    # Sample findings with variety
    findings = [
        {'name': 'SQL Injection', 'module': 'sqli', 'severity': 'Critical'},
        {'name': 'SQL Injection', 'module': 'sqli', 'severity': 'High'},
        {'name': 'Cross-Site Scripting (XSS)', 'module': 'xss', 'severity': 'High'},
        {'name': 'Server-Side Request Forgery (SSRF)', 'module': 'ssrf', 'severity': 'High'},
        {'name': 'Path Traversal', 'module': 'lfi_rfi', 'severity': 'Medium'},
        {'name': 'Missing Security Headers', 'module': 'insecure_headers', 'severity': 'Low'},
    ]
    
    mapper = ComplianceMapper()
    
    # Generate summary
    summary = mapper.generate_compliance_summary(findings)
    
    print("📊 Compliance Summary:\n")
    
    # OWASP
    owasp = summary['owasp_top10']
    print(f"🎯 OWASP Top 10: {owasp['count']} categories affected")
    for category in owasp['categories_affected']:
        print(f"   • {category}")
    
    # CWE
    cwe = summary['cwe']
    print(f"\n🔍 CWE: {cwe['count']} unique weaknesses")
    cwe_list = ', '.join([f"CWE-{cwe_id}" for cwe_id in cwe['weaknesses_found']])
    print(f"   {cwe_list}")
    
    # PCI-DSS
    pci = summary['pci_dss']
    print(f"\n💳 PCI-DSS v4.0: {pci['count']} requirements violated")
    for req in pci['requirements_violated'][:5]:
        print(f"   • Requirement {req}")
    
    # HIPAA
    hipaa = summary['hipaa']
    print(f"\n🏥 HIPAA Security Rule: {hipaa['count']} controls affected")
    for control in hipaa['controls_affected'][:5]:
        print(f"   • {control}")


def demo_report_generation():
    """Demonstrate full report generation."""
    print("\n" + "="*70)
    print("DEMO 3: Full Compliance Report Generation")
    print("="*70 + "\n")
    
    # Comprehensive findings set
    findings = [
        {
            'name': 'SQL Injection',
            'module': 'sqli',
            'severity': 'Critical',
            'url': 'http://example.com/search',
            'parameter': 'q',
            'payload': "' OR '1'='1",
            'evidence': 'SQL error revealed',
            'recommendation': 'Use parameterized queries with proper input validation'
        },
        {
            'name': 'SQL Injection',
            'module': 'sqli',
            'severity': 'High',
            'url': 'http://example.com/login',
            'parameter': 'username',
            'payload': "admin' --",
            'evidence': 'Authentication bypassed',
            'recommendation': 'Use parameterized queries with proper input validation'
        },
        {
            'name': 'Cross-Site Scripting (XSS) - Reflected',
            'module': 'xss',
            'severity': 'High',
            'url': 'http://example.com/search',
            'parameter': 'q',
            'payload': '<script>alert(document.cookie)</script>',
            'evidence': 'Script executed in browser',
            'recommendation': 'Implement context-aware output encoding and CSP'
        },
        {
            'name': 'Server-Side Request Forgery (SSRF)',
            'module': 'ssrf',
            'severity': 'High',
            'url': 'http://example.com/fetch',
            'parameter': 'url',
            'payload': 'http://169.254.169.254/latest/meta-data/',
            'evidence': 'Internal metadata accessed',
            'recommendation': 'Whitelist allowed domains and implement URL validation'
        },
        {
            'name': 'Broken Object Level Authorization (BOLA/IDOR)',
            'module': 'api_vulnerabilities',
            'severity': 'High',
            'url': 'http://example.com/api/users/123',
            'parameter': 'id',
            'payload': '456',
            'evidence': 'Unauthorized user data accessed',
            'recommendation': 'Implement proper authorization checks for every request'
        },
        {
            'name': 'Path Traversal',
            'module': 'lfi_rfi',
            'severity': 'Medium',
            'url': 'http://example.com/download',
            'parameter': 'file',
            'payload': '../../../etc/passwd',
            'evidence': 'System file accessed',
            'recommendation': 'Use whitelist of allowed files and sanitize file paths'
        },
        {
            'name': 'Missing Security Headers',
            'module': 'insecure_headers',
            'severity': 'Low',
            'url': 'http://example.com/',
            'parameter': 'N/A',
            'payload': 'N/A',
            'evidence': 'X-Frame-Options header missing',
            'recommendation': 'Implement security headers: HSTS, CSP, X-Frame-Options'
        }
    ]
    
    # Generate report
    generator = ComplianceReportGenerator()
    report = generator.generate_compliance_report(
        findings,
        output_path='demo_compliance_report',
        formats=['json', 'markdown', 'html']
    )
    
    # Display executive summary
    exec_summary = report['executive_summary']
    
    print("📊 Executive Summary:\n")
    print(f"🎯 Overall Status: {exec_summary['overall_status']}")
    print(f"🔢 Risk Score: {exec_summary['risk_score']}/100")
    
    print(f"\n📈 Severity Breakdown:")
    for severity, count in exec_summary['severity_breakdown'].items():
        if count > 0:
            print(f"   • {severity}: {count}")
    
    print(f"\n⚠️  Key Concerns:")
    for concern in exec_summary['key_concerns']:
        print(f"   • {concern}")
    
    print(f"\n📋 Standards Impacted:")
    standards = exec_summary['standards_impacted']
    print(f"   • OWASP Categories: {standards['owasp_categories']}")
    print(f"   • CWE Weaknesses: {standards['cwe_weaknesses']}")
    print(f"   • PCI-DSS Requirements: {standards['pci_requirements']}")
    print(f"   • HIPAA Controls: {standards['hipaa_controls']}")
    
    print(f"\n💾 Generated Report Files:")
    print(f"   • demo_compliance_report.json")
    print(f"   • demo_compliance_report.md")
    print(f"   • demo_compliance_report.html")
    
    print("\n✅ Full compliance report generated successfully!")


def demo_remediation_priorities():
    """Demonstrate remediation prioritization."""
    print("\n" + "="*70)
    print("DEMO 4: Remediation Priorities")
    print("="*70 + "\n")
    
    findings = [
        {'name': 'SQL Injection', 'module': 'sqli', 'severity': 'Critical', 
         'url': 'http://example.com/search', 'recommendation': 'Use parameterized queries'},
        {'name': 'SQL Injection', 'module': 'sqli', 'severity': 'High',
         'url': 'http://example.com/login', 'recommendation': 'Use parameterized queries'},
        {'name': 'Cross-Site Scripting (XSS)', 'module': 'xss', 'severity': 'High',
         'url': 'http://example.com/comment', 'recommendation': 'Implement output encoding'},
        {'name': 'Cross-Site Scripting (XSS)', 'module': 'xss', 'severity': 'Medium',
         'url': 'http://example.com/search', 'recommendation': 'Implement output encoding'},
        {'name': 'Missing Security Headers', 'module': 'insecure_headers', 'severity': 'Low',
         'url': 'http://example.com/', 'recommendation': 'Add security headers'},
    ]
    
    generator = ComplianceReportGenerator()
    report = generator.generate_compliance_report(findings)
    
    priorities = report['remediation_priorities']
    
    print("🎯 Remediation Priorities (by impact):\n")
    
    for i, priority in enumerate(priorities, 1):
        print(f"{i}. {priority['vulnerability_type']}")
        print(f"   • Occurrences: {priority['count']}")
        print(f"   • Priority Score: {priority['priority_score']}")
        print(f"   • Standards Affected: {', '.join(priority['affected_standards'])}")
        print(f"   • Recommendation: {priority['recommendation']}")
        print()


def main():
    """Run all demos."""
    print("\n" + "="*70)
    print("🛡️  ARGUS COMPLIANCE MAPPING SYSTEM - DEMONSTRATION")
    print("="*70)
    
    try:
        demo_basic_mapping()
        demo_compliance_summary()
        demo_report_generation()
        demo_remediation_priorities()
        
        print("\n" + "="*70)
        print("✅ All demos completed successfully!")
        print("="*70 + "\n")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
