"""Reporting engine for scan findings."""
import json
from datetime import datetime
from typing import Dict, List, Optional

# Import compliance mapper
try:
    from argus.compliance.mappings import ComplianceMapper
    from argus.compliance.reporting import generate_compliance_cli_report
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False


class CLIReporter:
    """Console-based reporting with color-coded output."""
    
    # ANSI color codes
    COLORS = {
        'Critical': '\033[95m',  # Magenta
        'High': '\033[91m',      # Red
        'Medium': '\033[93m',    # Yellow
        'Low': '\033[94m',       # Blue
        'Info': '\033[96m',      # Cyan
        'Reset': '\033[0m',      # Reset
        'Bold': '\033[1m',       # Bold
        'Green': '\033[92m',     # Green
        'Dim': '\033[2m',        # Dim
    }
    
    SEVERITY_ICONS = {
        'Critical': '🔴',
        'High': '🔴',
        'Medium': '🟡',
        'Low': '🔵',
        'Info': '⚪',
    }
    
    def __init__(self, config: dict):
        """Initialize CLI reporter.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.use_color = True  # Could be made configurable
        
        # Initialize compliance mapper if available
        if COMPLIANCE_AVAILABLE and config.get('enable_compliance', True):
            self.compliance_mapper = ComplianceMapper(config)
            self.show_compliance = True
        else:
            self.compliance_mapper = None
            self.show_compliance = False
    
    def _colorize(self, text: str, severity: str) -> str:
        """Add color to text based on severity.
        
        Args:
            text: Text to colorize
            severity: Severity level
        
        Returns:
            str: Colorized text
        """
        if not self.use_color:
            return text
        
        color = self.COLORS.get(severity, self.COLORS['Reset'])
        reset = self.COLORS['Reset']
        return f"{color}{text}{reset}"
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by grouping similar issues across multiple URLs.
        
        For issues like missing security headers that appear on many URLs,
        group them into a single finding with multiple affected URLs.
        
        Args:
            findings: List of all findings
        
        Returns:
            List of deduplicated findings
        """
        # Group findings by (name, severity, parameter, payload)
        # This groups identical findings that only differ by URL
        groups = {}
        
        for finding in findings:
            # Create a key that uniquely identifies the "type" of finding
            key = (
                finding['name'],
                finding['severity'],
                finding.get('parameter', 'N/A'),
                finding.get('payload', 'N/A')[:50]  # First 50 chars of payload
            )
            
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)
        
        # Convert groups back to deduplicated findings
        deduplicated = []
        for key, group in groups.items():
            if len(group) == 1:
                # Only one instance, keep as-is
                deduplicated.append(group[0])
            else:
                # Multiple instances, create a grouped finding
                first = group[0]
                urls = [f['url'] for f in group]
                
                # Create new finding with multiple URLs
                grouped_finding = first.copy()
                grouped_finding['url'] = urls[0]  # Primary URL
                grouped_finding['affected_urls'] = urls  # All affected URLs
                grouped_finding['affected_count'] = len(urls)
                
                # Update evidence to mention multiple URLs
                if 'Missing Security Header' in first['name'] or 'CORS' in first['name']:
                    grouped_finding['evidence'] = f"{first['evidence']} Found on {len(urls)} endpoints."
                
                deduplicated.append(grouped_finding)
        
        return deduplicated
    
    def generate_report(self, findings: List[Dict], site_map: List[Dict], stats: Dict) -> None:
        """Generate and print console report.
        
        Args:
            findings: List of vulnerability findings
            site_map: Discovered site map (unused in basic version)
            stats: Scan statistics
        """
        # Deduplicate findings first
        original_count = len(findings)
        findings = self._deduplicate_findings(findings)
        
        if self.config.get('verbose') and original_count > len(findings):
            print(f"\n{self.COLORS['Dim']}ℹ️  Deduplicated {original_count} findings → {len(findings)} unique issues{self.COLORS['Reset']}")
        
        # Enrich findings with compliance data if enabled
        if self.show_compliance and self.compliance_mapper and findings:
            findings = self.compliance_mapper.enrich_findings(findings)
        
        print("\n" + "="*70)
        print(f"{self.COLORS['Bold']}🔍 ARGUS SCAN RESULTS{self.COLORS['Reset']}")
        print("="*70 + "\n")
        
        if not findings:
            print(f"{self.COLORS['Green']}✅ No vulnerabilities found!{self.COLORS['Reset']}\n")
        else:
            # Sort by severity
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_findings = sorted(
                findings,
                key=lambda f: (severity_order.get(f['severity'], 5), f['name'])
            )
            
            # Count by severity
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for finding in findings:
                sev = finding.get('severity', 'Info')
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            # Display summary
            summary_parts = []
            if severity_counts['Critical'] > 0:
                summary_parts.append(self._colorize(f"Critical: {severity_counts['Critical']}", 'Critical'))
            if severity_counts['High'] > 0:
                summary_parts.append(self._colorize(f"High: {severity_counts['High']}", 'High'))
            if severity_counts['Medium'] > 0:
                summary_parts.append(self._colorize(f"Medium: {severity_counts['Medium']}", 'Medium'))
            if severity_counts['Low'] > 0:
                summary_parts.append(self._colorize(f"Low: {severity_counts['Low']}", 'Low'))
            if severity_counts['Info'] > 0:
                summary_parts.append(self._colorize(f"Info: {severity_counts['Info']}", 'Info'))
            
            print(f"Found {self._colorize(str(len(findings)), 'Bold')} issue(s): {' | '.join(summary_parts)}\n")
            
            for idx, finding in enumerate(sorted_findings, 1):
                severity = finding['severity']
                icon = self.SEVERITY_ICONS.get(severity, '⚫')
                
                # Header
                print(f"{'─'*70}")
                title = f"{icon} [{idx}/{len(findings)}] {self._colorize(severity.upper(), severity)}: {finding['name']}"
                if 'affected_count' in finding and finding['affected_count'] > 1:
                    title += f" {self.COLORS['Dim']}(on {finding['affected_count']} endpoints){self.COLORS['Reset']}"
                print(f"{self.COLORS['Bold']}{title}{self.COLORS['Reset']}")
                print(f"{'─'*70}")
                
                # Details
                if 'affected_count' in finding and finding['affected_count'] > 1:
                    print(f"{self.COLORS['Dim']}Affected URLs:{self.COLORS['Reset']} {finding['affected_count']} endpoints")
                    # Show first few URLs
                    urls_to_show = finding['affected_urls'][:5]
                    for url in urls_to_show:
                        print(f"  • {url}")
                    if len(finding['affected_urls']) > 5:
                        print(f"  {self.COLORS['Dim']}... and {len(finding['affected_urls']) - 5} more{self.COLORS['Reset']}")
                else:
                    print(f"{self.COLORS['Dim']}URL:{self.COLORS['Reset']} {finding['url']}")
                
                if finding['parameter'] != 'N/A':
                    print(f"{self.COLORS['Dim']}Parameter:{self.COLORS['Reset']} {finding['parameter']}")
                
                if finding['payload'] != 'N/A':
                    payload = finding['payload']
                    if len(payload) > 100:
                        payload = payload[:97] + "..."
                    print(f"{self.COLORS['Dim']}Payload:{self.COLORS['Reset']} {payload}")
                
                evidence = finding['evidence']
                if len(evidence) > 200:
                    evidence = evidence[:197] + "..."
                print(f"{self.COLORS['Dim']}Evidence:{self.COLORS['Reset']} {evidence}")
                
                # Compliance information (if available)
                if self.show_compliance and 'compliance' in finding:
                    compliance = finding['compliance']
                    owasp = compliance.get('owasp', {})
                    cwe_ids = compliance.get('cwe_ids', [])
                    
                    if owasp.get('id') or cwe_ids:
                        print(f"\n{self.COLORS['Dim']}📋 Compliance:{self.COLORS['Reset']}")
                        if owasp.get('id'):
                            print(f"   OWASP: {owasp['id']} - {owasp.get('category', 'N/A')}")
                        if cwe_ids:
                            cwe_list = ', '.join([f"CWE-{cwe_id}" for cwe_id in cwe_ids[:3]])
                            print(f"   CWE: {cwe_list}")
                
                # Recommendation (if present)
                if 'recommendation' in finding and finding['recommendation']:
                    print(f"\n{self.COLORS['Green']}💡 Recommendation:{self.COLORS['Reset']}")
                    # Word wrap recommendation at 65 chars
                    rec = finding['recommendation']
                    words = rec.split()
                    lines = []
                    current_line = "   "
                    for word in words:
                        if len(current_line) + len(word) + 1 > 68:
                            lines.append(current_line)
                            current_line = "   " + word
                        else:
                            if current_line == "   ":
                                current_line += word
                            else:
                                current_line += " " + word
                    if current_line.strip():
                        lines.append(current_line)
                    print('\n'.join(lines))
                
                print()  # Extra line between findings
        
        # Print statistics
        print("="*70)
        print(f"{self.COLORS['Bold']}📊 SCAN STATISTICS{self.COLORS['Reset']}")
        print("="*70)
        print(f"URLs scanned: {stats.get('urls_scanned', 0)}")
        print(f"Parameters tested: {stats.get('parameters_tested', 0)}")
        print(f"Modules run: {stats.get('modules_run', 0)}")
        if stats.get('scan_duration'):
            print(f"Scan duration: {stats['scan_duration']:.2f}s")
        if stats.get('errors'):
            print(f"⚠️  Errors: {stats['errors']}")
        print()
        
        # Print compliance summary if enabled
        if self.show_compliance and self.compliance_mapper and findings:
            generate_compliance_cli_report(findings, self.compliance_mapper)


class JSONReporter:
    """JSON-based reporting for tool integration."""
    
    def __init__(self, config: dict):
        """Initialize JSON reporter.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        
        # Initialize compliance mapper if available
        if COMPLIANCE_AVAILABLE and config.get('enable_compliance', True):
            self.compliance_mapper = ComplianceMapper(config)
            self.include_compliance = True
        else:
            self.compliance_mapper = None
            self.include_compliance = False
    
    def generate_report(
        self,
        findings: List[Dict],
        site_map: List[Dict],
        stats: Dict,
        output_file: Optional[str] = None
    ) -> None:
        """Generate JSON report.
        
        Args:
            findings: List of vulnerability findings
            site_map: Discovered site map
            stats: Scan statistics
            output_file: Output file path (prints to stdout if None)
        """
        # Enrich findings with compliance data if enabled
        if self.include_compliance and self.compliance_mapper and findings:
            findings = self.compliance_mapper.enrich_findings(findings)
        
        # Calculate summary statistics
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for finding in findings:
            sev = finding.get('severity', 'Info')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        report = {
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat() + 'Z',
            'target': self.config.get('seed_url', 'unknown'),
            'scan_info': {
                'target': self.config.get('seed_url', 'unknown'),
                'timestamp': datetime.now().isoformat() + 'Z',
                'scanner_version': '1.0.0'
            },
            'findings': findings,
            'summary': {
                'total': len(findings),
                'by_severity': severity_counts
            },
            'site_map': site_map,
            'statistics': stats
        }
        
        # Add compliance summary if enabled
        if self.include_compliance and self.compliance_mapper and findings:
            report['compliance_summary'] = self.compliance_mapper.generate_compliance_summary(findings)
        
        json_output = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
        else:
            print(json_output)
        
        return report
