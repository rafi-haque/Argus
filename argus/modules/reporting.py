"""Reporting engine for scan findings."""
import json
from datetime import datetime
from typing import Dict, List, Optional


class CLIReporter:
    """Console-based reporting with color-coded output."""
    
    # ANSI color codes
    COLORS = {
        'High': '\033[91m',      # Red
        'Medium': '\033[93m',    # Yellow
        'Low': '\033[94m',       # Blue
        'Info': '\033[96m',      # Cyan
        'Reset': '\033[0m',      # Reset
        'Bold': '\033[1m',       # Bold
        'Green': '\033[92m',     # Green
    }
    
    SEVERITY_ICONS = {
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
    
    def generate_report(self, findings: List[Dict], site_map: List[Dict], stats: Dict) -> None:
        """Generate and print console report.
        
        Args:
            findings: List of vulnerability findings
            site_map: Discovered site map (unused in basic version)
            stats: Scan statistics
        """
        print("\n" + "="*70)
        print(f"{self.COLORS['Bold']}🔍 ARGUS SCAN RESULTS{self.COLORS['Reset']}")
        print("="*70 + "\n")
        
        if not findings:
            print(f"{self.COLORS['Green']}✅ No vulnerabilities found!{self.COLORS['Reset']}\n")
        else:
            # Sort by severity
            severity_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}
            sorted_findings = sorted(
                findings,
                key=lambda f: (severity_order.get(f['severity'], 4), f['name'])
            )
            
            print(f"Found {len(findings)} issue(s):\n")
            
            for idx, finding in enumerate(sorted_findings, 1):
                severity = finding['severity']
                icon = self.SEVERITY_ICONS.get(severity, '⚫')
                
                print(f"{icon} {self._colorize(severity.upper(), severity)}: {finding['name']}")
                print(f"   URL: {finding['url']}")
                
                if finding['parameter'] != 'N/A':
                    print(f"   Parameter: {finding['parameter']}")
                
                if finding['payload'] != 'N/A':
                    # Truncate long payloads
                    payload = finding['payload']
                    if len(payload) > 100:
                        payload = payload[:97] + "..."
                    print(f"   Payload: {payload}")
                
                # Truncate long evidence
                evidence = finding['evidence']
                if len(evidence) > 150:
                    evidence = evidence[:147] + "..."
                print(f"   Evidence: {evidence}")
                print()
        
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


class JSONReporter:
    """JSON-based reporting for tool integration."""
    
    def __init__(self, config: dict):
        """Initialize JSON reporter.
        
        Args:
            config: Scanner configuration
        """
        self.config = config
    
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
        # Calculate summary statistics
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
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
        
        json_output = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
        else:
            print(json_output)
        
        return report
