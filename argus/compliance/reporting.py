"""Compliance report generation for Argus findings."""

from typing import Dict, List
from datetime import datetime
from pathlib import Path
import json
import yaml

from argus.compliance.mappings import ComplianceMapper


class ComplianceReportGenerator:
    """Generates compliance reports from scan findings."""
    
    def __init__(self, config: Dict = None):
        """Initialize compliance report generator.
        
        Args:
            config: Optional configuration dict
        """
        self.config = config or {}
        self.mapper = ComplianceMapper(config)
    
    def generate_compliance_report(self, findings: List[Dict], 
                                  output_path: str = None,
                                  formats: List[str] = None) -> Dict:
        """Generate comprehensive compliance report.
        
        Args:
            findings: List of vulnerability findings
            output_path: Optional path to save report
            formats: List of output formats ['json', 'yaml', 'html', 'markdown']
        
        Returns:
            Dict: Compliance report data
        """
        if formats is None:
            formats = ['json']
        
        # Enrich findings with compliance metadata
        enriched_findings = self.mapper.enrich_findings(findings)
        
        # Generate summary
        summary = self.mapper.generate_compliance_summary(findings)
        
        # Build report structure
        report = {
            'metadata': {
                'scan_date': datetime.now().isoformat(),
                'scanner': 'Argus',
                'version': '2.0.0',
                'total_findings': len(findings),
                'standards_covered': ['OWASP Top 10 2021', 'CWE', 'PCI-DSS v4.0', 'HIPAA Security Rule']
            },
            'executive_summary': self._generate_executive_summary(enriched_findings, summary),
            'compliance_summary': summary,
            'findings_by_standard': self._organize_by_standard(enriched_findings),
            'remediation_priorities': self._generate_remediation_priorities(enriched_findings),
            'detailed_findings': enriched_findings
        }
        
        # Save report in requested formats
        if output_path:
            for fmt in formats:
                self._save_report(report, output_path, fmt)
        
        return report
    
    def _generate_executive_summary(self, findings: List[Dict], summary: Dict) -> Dict:
        """Generate executive summary of compliance findings.
        
        Args:
            findings: Enriched findings
            summary: Compliance summary
        
        Returns:
            Dict: Executive summary
        """
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        risk_score = (
            severity_counts['Critical'] * 10 +
            severity_counts['High'] * 5 +
            severity_counts['Medium'] * 2 +
            severity_counts['Low'] * 1
        )
        risk_score = min(100, risk_score)
        
        # Determine overall compliance status
        if risk_score >= 80:
            status = 'Non-Compliant - Critical Issues'
        elif risk_score >= 50:
            status = 'Partially Compliant - Significant Issues'
        elif risk_score >= 20:
            status = 'Mostly Compliant - Minor Issues'
        else:
            status = 'Compliant - No Critical Issues'
        
        return {
            'overall_status': status,
            'risk_score': risk_score,
            'severity_breakdown': severity_counts,
            'standards_impacted': {
                'owasp_categories': summary['owasp_top10']['count'],
                'cwe_weaknesses': summary['cwe']['count'],
                'pci_requirements': summary['pci_dss']['count'],
                'hipaa_controls': summary['hipaa']['count']
            },
            'key_concerns': self._identify_key_concerns(findings)
        }
    
    def _identify_key_concerns(self, findings: List[Dict]) -> List[str]:
        """Identify key compliance concerns.
        
        Args:
            findings: Enriched findings
        
        Returns:
            List[str]: Key concerns
        """
        concerns = []
        
        # Check for critical vulnerabilities
        critical_findings = [f for f in findings if f.get('severity') == 'Critical']
        if critical_findings:
            concerns.append(f"{len(critical_findings)} critical vulnerabilities requiring immediate attention")
        
        # Check for injection flaws
        injection_types = ['sql injection', 'xss', 'command injection', 'xxe']
        injection_findings = [
            f for f in findings 
            if any(vuln_type in f.get('name', '').lower() for vuln_type in injection_types)
        ]
        if injection_findings:
            concerns.append(f"Injection vulnerabilities detected ({len(injection_findings)} findings)")
        
        # Check for access control issues
        access_control_findings = [
            f for f in findings
            if 'authorization' in f.get('name', '').lower() or 'access control' in f.get('name', '').lower()
        ]
        if access_control_findings:
            concerns.append(f"Access control issues present ({len(access_control_findings)} findings)")
        
        # Check for sensitive data exposure
        data_exposure_findings = [
            f for f in findings
            if 'data exposure' in f.get('name', '').lower() or 'sensitive' in f.get('name', '').lower()
        ]
        if data_exposure_findings:
            concerns.append(f"Sensitive data exposure risks ({len(data_exposure_findings)} findings)")
        
        return concerns[:5]  # Top 5 concerns
    
    def _organize_by_standard(self, findings: List[Dict]) -> Dict:
        """Organize findings by compliance standard.
        
        Args:
            findings: Enriched findings
        
        Returns:
            Dict: Findings organized by standard
        """
        by_standard = {
            'owasp': {},
            'cwe': {},
            'pci_dss': {},
            'hipaa': {}
        }
        
        for finding in findings:
            compliance = finding.get('compliance', {})
            
            # OWASP
            owasp = compliance.get('owasp', {})
            owasp_id = owasp.get('id')
            if owasp_id:
                if owasp_id not in by_standard['owasp']:
                    by_standard['owasp'][owasp_id] = {
                        'category': owasp.get('category'),
                        'findings': []
                    }
                by_standard['owasp'][owasp_id]['findings'].append({
                    'name': finding.get('name'),
                    'severity': finding.get('severity'),
                    'url': finding.get('url'),
                    'parameter': finding.get('parameter')
                })
            
            # CWE
            for cwe_id in compliance.get('cwe_ids', []):
                cwe_key = f"CWE-{cwe_id}"
                if cwe_key not in by_standard['cwe']:
                    by_standard['cwe'][cwe_key] = {'findings': []}
                by_standard['cwe'][cwe_key]['findings'].append({
                    'name': finding.get('name'),
                    'severity': finding.get('severity'),
                    'url': finding.get('url')
                })
            
            # PCI-DSS
            for requirement in compliance.get('pci_dss', []):
                if requirement not in by_standard['pci_dss']:
                    by_standard['pci_dss'][requirement] = {'findings': []}
                by_standard['pci_dss'][requirement]['findings'].append({
                    'name': finding.get('name'),
                    'severity': finding.get('severity'),
                    'url': finding.get('url')
                })
            
            # HIPAA
            for control in compliance.get('hipaa', []):
                if control not in by_standard['hipaa']:
                    by_standard['hipaa'][control] = {'findings': []}
                by_standard['hipaa'][control]['findings'].append({
                    'name': finding.get('name'),
                    'severity': finding.get('severity'),
                    'url': finding.get('url')
                })
        
        return by_standard
    
    def _generate_remediation_priorities(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation recommendations.
        
        Args:
            findings: Enriched findings
        
        Returns:
            List[Dict]: Prioritized remediation actions
        """
        priorities = []
        
        # Group by vulnerability type
        by_type = {}
        for finding in findings:
            vuln_type = finding.get('name')
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(finding)
        
        # Calculate priority for each type
        for vuln_type, vuln_findings in by_type.items():
            # Get severity weights
            severity_weight = {
                'Critical': 4,
                'High': 3,
                'Medium': 2,
                'Low': 1
            }
            
            total_weight = sum(
                severity_weight.get(f.get('severity', 'Medium'), 2)
                for f in vuln_findings
            )
            
            # Get compliance impact
            compliance_standards = set()
            for f in vuln_findings:
                compliance = f.get('compliance', {})
                if compliance.get('owasp', {}).get('id'):
                    compliance_standards.add('OWASP')
                if compliance.get('cwe_ids'):
                    compliance_standards.add('CWE')
                if compliance.get('pci_dss'):
                    compliance_standards.add('PCI-DSS')
                if compliance.get('hipaa'):
                    compliance_standards.add('HIPAA')
            
            # Get remediation from first finding
            recommendation = vuln_findings[0].get('recommendation', 'Apply security best practices')
            
            priorities.append({
                'vulnerability_type': vuln_type,
                'count': len(vuln_findings),
                'priority_score': total_weight,
                'affected_standards': sorted(list(compliance_standards)),
                'recommendation': recommendation,
                'affected_urls': [f.get('url') for f in vuln_findings[:5]]  # First 5
            })
        
        # Sort by priority score (highest first)
        priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priorities
    
    def _save_report(self, report: Dict, base_path: str, format: str):
        """Save report in specified format.
        
        Args:
            report: Report data
            base_path: Base file path (without extension)
            format: Output format
        """
        output_path = Path(base_path)
        
        if format == 'json':
            file_path = output_path.with_suffix('.json')
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        elif format == 'yaml':
            file_path = output_path.with_suffix('.yaml')
            with open(file_path, 'w') as f:
                yaml.dump(report, f, default_flow_style=False, sort_keys=False)
        
        elif format == 'markdown':
            file_path = output_path.with_suffix('.md')
            markdown_content = self._generate_markdown(report)
            with open(file_path, 'w') as f:
                f.write(markdown_content)
        
        elif format == 'html':
            file_path = output_path.with_suffix('.html')
            html_content = self._generate_html(report)
            with open(file_path, 'w') as f:
                f.write(html_content)
    
    def _generate_markdown(self, report: Dict) -> str:
        """Generate Markdown report.
        
        Args:
            report: Report data
        
        Returns:
            str: Markdown content
        """
        md = []
        metadata = report['metadata']
        exec_summary = report['executive_summary']
        compliance_summary = report['compliance_summary']
        
        # Header
        md.append("# Compliance Security Assessment Report")
        md.append(f"\n**Generated:** {metadata['scan_date']}")
        md.append(f"**Scanner:** {metadata['scanner']} v{metadata['version']}")
        md.append(f"**Total Findings:** {metadata['total_findings']}\n")
        
        # Executive Summary
        md.append("## Executive Summary\n")
        md.append(f"**Overall Status:** {exec_summary['overall_status']}")
        md.append(f"**Risk Score:** {exec_summary['risk_score']}/100\n")
        
        # Severity Breakdown
        md.append("### Severity Breakdown")
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        for severity, count in exec_summary['severity_breakdown'].items():
            md.append(f"| {severity} | {count} |")
        md.append("")
        
        # Key Concerns
        if exec_summary.get('key_concerns'):
            md.append("### Key Concerns")
            for concern in exec_summary['key_concerns']:
                md.append(f"- {concern}")
            md.append("")
        
        # Compliance Summary
        md.append("## Compliance Standards Impact\n")
        
        # OWASP
        owasp = compliance_summary['owasp_top10']
        md.append(f"### OWASP Top 10: {owasp['count']} categories affected")
        for category_id in owasp['categories_affected']:
            md.append(f"- {category_id}")
        md.append("")
        
        # CWE
        cwe = compliance_summary['cwe']
        md.append(f"### CWE: {cwe['count']} weaknesses identified")
        cwe_list = ', '.join([f"CWE-{cwe_id}" for cwe_id in cwe['weaknesses_found'][:10]])
        md.append(f"**Top CWEs:** {cwe_list}")
        md.append("")
        
        # PCI-DSS
        pci = compliance_summary['pci_dss']
        md.append(f"### PCI-DSS v4.0: {pci['count']} requirements violated")
        for req in pci['requirements_violated'][:10]:
            md.append(f"- Requirement {req}")
        md.append("")
        
        # HIPAA
        hipaa = compliance_summary['hipaa']
        md.append(f"### HIPAA Security Rule: {hipaa['count']} controls affected")
        for control in hipaa['controls_affected'][:10]:
            md.append(f"- {control}")
        md.append("")
        
        # Remediation Priorities
        md.append("## Remediation Priorities\n")
        priorities = report['remediation_priorities'][:10]  # Top 10
        for i, priority in enumerate(priorities, 1):
            md.append(f"### {i}. {priority['vulnerability_type']}")
            md.append(f"- **Occurrences:** {priority['count']}")
            md.append(f"- **Priority Score:** {priority['priority_score']}")
            md.append(f"- **Standards Affected:** {', '.join(priority['affected_standards'])}")
            md.append(f"- **Recommendation:** {priority['recommendation']}")
            md.append("")
        
        return '\n'.join(md)
    
    def _generate_html(self, report: Dict) -> str:
        """Generate HTML report.
        
        Args:
            report: Report data
        
        Returns:
            str: HTML content
        """
        metadata = report['metadata']
        exec_summary = report['executive_summary']
        compliance_summary = report['compliance_summary']
        
        # Determine risk color
        risk_score = exec_summary['risk_score']
        if risk_score >= 80:
            risk_color = '#d32f2f'  # Red
        elif risk_score >= 50:
            risk_color = '#f57c00'  # Orange
        elif risk_score >= 20:
            risk_color = '#fbc02d'  # Yellow
        else:
            risk_color = '#388e3c'  # Green
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Security Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: #1976d2;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .risk-score {{
            font-size: 48px;
            font-weight: bold;
            color: {risk_color};
            text-align: center;
            margin: 20px 0;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            margin: 2px;
        }}
        .critical {{ background: #d32f2f; color: white; }}
        .high {{ background: #f57c00; color: white; }}
        .medium {{ background: #fbc02d; color: black; }}
        .low {{ background: #388e3c; color: white; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f5f5f5;
            font-weight: bold;
        }}
        .standard-section {{
            margin: 20px 0;
        }}
        .priority-item {{
            background: #f9f9f9;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #1976d2;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Compliance Security Assessment Report</h1>
        <p><strong>Generated:</strong> {metadata['scan_date']}</p>
        <p><strong>Scanner:</strong> {metadata['scanner']} v{metadata['version']}</p>
        <p><strong>Total Findings:</strong> {metadata['total_findings']}</p>
    </div>
    
    <div class="card">
        <h2>Executive Summary</h2>
        <p><strong>Overall Status:</strong> {exec_summary['overall_status']}</p>
        <div class="risk-score">{risk_score}/100</div>
        <p style="text-align: center; color: #666;">Risk Score</p>
        
        <h3>Severity Breakdown</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
"""
        
        for severity, count in exec_summary['severity_breakdown'].items():
            html += f"""            <tr>
                <td><span class="severity-badge {severity.lower()}">{severity}</span></td>
                <td>{count}</td>
            </tr>
"""
        
        html += """        </table>
"""
        
        if exec_summary.get('key_concerns'):
            html += """        <h3>Key Concerns</h3>
        <ul>
"""
            for concern in exec_summary['key_concerns']:
                html += f"""            <li>{concern}</li>
"""
            html += """        </ul>
"""
        
        html += """    </div>
    
    <div class="card">
        <h2>Compliance Standards Impact</h2>
"""
        
        # OWASP
        owasp = compliance_summary['owasp_top10']
        html += f"""        <div class="standard-section">
            <h3>📋 OWASP Top 10: {owasp['count']} categories affected</h3>
            <p>{', '.join(owasp['categories_affected'])}</p>
        </div>
"""
        
        # CWE
        cwe = compliance_summary['cwe']
        cwe_list = ', '.join([f"CWE-{cwe_id}" for cwe_id in cwe['weaknesses_found'][:15]])
        html += f"""        <div class="standard-section">
            <h3>🔍 CWE: {cwe['count']} weaknesses identified</h3>
            <p><strong>Top CWEs:</strong> {cwe_list}</p>
        </div>
"""
        
        # PCI-DSS
        pci = compliance_summary['pci_dss']
        pci_list = ', '.join(pci['requirements_violated'][:15])
        html += f"""        <div class="standard-section">
            <h3>💳 PCI-DSS v4.0: {pci['count']} requirements violated</h3>
            <p><strong>Requirements:</strong> {pci_list}</p>
        </div>
"""
        
        # HIPAA
        hipaa = compliance_summary['hipaa']
        html += f"""        <div class="standard-section">
            <h3>🏥 HIPAA Security Rule: {hipaa['count']} controls affected</h3>
            <p>{', '.join(hipaa['controls_affected'][:10])}</p>
        </div>
"""
        
        html += """    </div>
    
    <div class="card">
        <h2>Remediation Priorities</h2>
"""
        
        priorities = report['remediation_priorities'][:10]
        for i, priority in enumerate(priorities, 1):
            html += f"""        <div class="priority-item">
            <h3>{i}. {priority['vulnerability_type']}</h3>
            <p><strong>Occurrences:</strong> {priority['count']} | <strong>Priority Score:</strong> {priority['priority_score']}</p>
            <p><strong>Standards Affected:</strong> {', '.join(priority['affected_standards'])}</p>
            <p><strong>Recommendation:</strong> {priority['recommendation']}</p>
        </div>
"""
        
        html += """    </div>
    
    <div class="card" style="background: #f5f5f5; text-align: center; padding: 15px;">
        <p style="margin: 0; color: #666;">Report generated by Argus Security Scanner</p>
    </div>
</body>
</html>
"""
        
        return html


def generate_compliance_cli_report(findings: List[Dict], mapper: ComplianceMapper):
    """Generate CLI-friendly compliance summary.
    
    Args:
        findings: List of findings
        mapper: ComplianceMapper instance
    """
    if not findings:
        return
    
    summary = mapper.generate_compliance_summary(findings)
    
    print("\n" + "="*70)
    print("📋 COMPLIANCE SUMMARY")
    print("="*70)
    
    # OWASP
    owasp = summary['owasp_top10']
    print(f"\n🎯 OWASP Top 10: {owasp['count']} categories affected")
    for category in owasp['categories_affected']:
        print(f"   • {category}")
    
    # CWE
    cwe = summary['cwe']
    print(f"\n🔍 CWE: {cwe['count']} weaknesses found")
    cwe_list = ', '.join([f"CWE-{cwe_id}" for cwe_id in cwe['weaknesses_found'][:10]])
    print(f"   Top 10: {cwe_list}")
    
    # PCI-DSS
    pci = summary['pci_dss']
    if pci['count'] > 0:
        print(f"\n💳 PCI-DSS v4.0: {pci['count']} requirements violated")
        for req in pci['requirements_violated'][:5]:
            print(f"   • Requirement {req}")
    
    # HIPAA
    hipaa = summary['hipaa']
    if hipaa['count'] > 0:
        print(f"\n🏥 HIPAA: {hipaa['count']} controls affected")
        for control in hipaa['controls_affected'][:5]:
            print(f"   • {control}")
    
    print("\n" + "="*70)
