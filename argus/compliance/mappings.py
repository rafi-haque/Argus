"""Compliance mapping system for Argus findings.

Maps vulnerabilities to industry standards:
- OWASP Top 10 (2021)
- CWE (Common Weakness Enumeration)
- PCI-DSS v4.0
- HIPAA Security Rule
"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class ComplianceMapping:
    """Represents a compliance mapping for a vulnerability."""
    
    owasp_category: Optional[str] = None
    owasp_id: Optional[str] = None
    cwe_ids: List[int] = field(default_factory=list)
    pci_dss_requirements: List[str] = field(default_factory=list)
    hipaa_controls: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    iso27001_controls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'owasp': {
                'category': self.owasp_category,
                'id': self.owasp_id
            },
            'cwe_ids': self.cwe_ids,
            'pci_dss': self.pci_dss_requirements,
            'hipaa': self.hipaa_controls,
            'nist': self.nist_controls,
            'iso27001': self.iso27001_controls
        }


class ComplianceMapper:
    """Maps vulnerability findings to compliance standards."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize compliance mapper.
        
        Args:
            config: Optional configuration dict
        """
        self.config = config or {}
        self.mappings = {}
        self._load_mappings()
    
    def _load_mappings(self):
        """Load compliance mappings from YAML files."""
        # Get mapping directory
        base_dir = Path(__file__).parent
        
        # Load OWASP Top 10 mappings
        owasp_file = base_dir / 'owasp_top10.yaml'
        if owasp_file.exists():
            with open(owasp_file) as f:
                self.owasp_mappings = yaml.safe_load(f)
        else:
            self.owasp_mappings = self._get_default_owasp_mappings()
        
        # Load CWE mappings
        cwe_file = base_dir / 'cwe_mappings.yaml'
        if cwe_file.exists():
            with open(cwe_file) as f:
                self.cwe_mappings = yaml.safe_load(f)
        else:
            self.cwe_mappings = self._get_default_cwe_mappings()
        
        # Load PCI-DSS mappings
        pci_file = base_dir / 'pci_dss.yaml'
        if pci_file.exists():
            with open(pci_file) as f:
                self.pci_mappings = yaml.safe_load(f)
        else:
            self.pci_mappings = self._get_default_pci_mappings()
        
        # Load HIPAA mappings
        hipaa_file = base_dir / 'hipaa.yaml'
        if hipaa_file.exists():
            with open(hipaa_file) as f:
                self.hipaa_mappings = yaml.safe_load(f)
        else:
            self.hipaa_mappings = self._get_default_hipaa_mappings()
    
    def map_finding(self, finding: Dict) -> ComplianceMapping:
        """Map a finding to compliance standards.
        
        Args:
            finding: Finding dict with 'name', 'module', 'severity', etc.
        
        Returns:
            ComplianceMapping: Compliance mapping for the finding
        """
        vuln_name = finding.get('name', '').lower()
        module_name = finding.get('module', '').lower()
        
        # Determine vulnerability type
        vuln_type = self._identify_vulnerability_type(vuln_name, module_name)
        
        # Map to standards
        mapping = ComplianceMapping()
        
        # OWASP Top 10
        if vuln_type in self.owasp_mappings:
            owasp_data = self.owasp_mappings[vuln_type]
            mapping.owasp_category = owasp_data.get('category')
            mapping.owasp_id = owasp_data.get('id')
        
        # CWE
        if vuln_type in self.cwe_mappings:
            mapping.cwe_ids = self.cwe_mappings[vuln_type].get('cwe_ids', [])
        
        # PCI-DSS
        if vuln_type in self.pci_mappings:
            mapping.pci_dss_requirements = self.pci_mappings[vuln_type].get('requirements', [])
        
        # HIPAA
        if vuln_type in self.hipaa_mappings:
            mapping.hipaa_controls = self.hipaa_mappings[vuln_type].get('controls', [])
        
        return mapping
    
    def _identify_vulnerability_type(self, vuln_name: str, module_name: str) -> str:
        """Identify vulnerability type from name and module.
        
        Args:
            vuln_name: Vulnerability name (lowercase)
            module_name: Module name (lowercase)
        
        Returns:
            str: Normalized vulnerability type
        """
        # SQL Injection
        if 'sql' in vuln_name or 'sqli' in module_name:
            return 'sql_injection'
        
        # XSS
        if 'xss' in vuln_name or 'cross-site scripting' in vuln_name:
            if 'stored' in vuln_name:
                return 'xss_stored'
            elif 'dom' in vuln_name:
                return 'xss_dom'
            return 'xss_reflected'
        
        # CSRF
        if 'csrf' in vuln_name or 'cross-site request forgery' in vuln_name:
            return 'csrf'
        
        # Authentication
        if 'authentication' in vuln_name or 'auth' in module_name:
            return 'broken_authentication'
        
        # Authorization
        if 'authorization' in vuln_name or 'bola' in vuln_name or 'idor' in vuln_name:
            return 'broken_access_control'
        
        # Injection
        if 'command injection' in vuln_name or 'os command' in vuln_name:
            return 'command_injection'
        if 'ldap injection' in vuln_name:
            return 'ldap_injection'
        if 'xml injection' in vuln_name or 'xxe' in vuln_name:
            return 'xxe'
        
        # SSRF
        if 'ssrf' in vuln_name or 'server-side request forgery' in vuln_name:
            return 'ssrf'
        
        # Path Traversal
        if 'path traversal' in vuln_name or 'directory traversal' in vuln_name or 'lfi' in vuln_name:
            return 'path_traversal'
        
        # File Upload
        if 'file upload' in vuln_name or 'upload' in module_name:
            return 'unrestricted_file_upload'
        
        # Deserialization
        if 'deserialization' in vuln_name:
            return 'insecure_deserialization'
        
        # Security Misconfiguration
        if 'header' in vuln_name or 'misconfiguration' in vuln_name:
            if 'cors' in vuln_name:
                return 'cors_misconfiguration'
            return 'security_misconfiguration'
        
        # Sensitive Data
        if 'sensitive data' in vuln_name or 'data exposure' in vuln_name:
            return 'sensitive_data_exposure'
        
        # Mass Assignment
        if 'mass assignment' in vuln_name:
            return 'mass_assignment'
        
        # Open Redirect
        if 'open redirect' in vuln_name or 'redirect' in module_name:
            return 'open_redirect'
        
        # Default
        return 'other'
    
    def enrich_finding(self, finding: Dict) -> Dict:
        """Enrich a finding with compliance metadata.
        
        Args:
            finding: Finding dict
        
        Returns:
            Dict: Enriched finding with compliance data
        """
        mapping = self.map_finding(finding)
        enriched = finding.copy()
        enriched['compliance'] = mapping.to_dict()
        return enriched
    
    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """Enrich multiple findings with compliance metadata.
        
        Args:
            findings: List of finding dicts
        
        Returns:
            List[Dict]: Enriched findings
        """
        return [self.enrich_finding(f) for f in findings]
    
    def generate_compliance_summary(self, findings: List[Dict]) -> Dict:
        """Generate compliance summary from findings.
        
        Args:
            findings: List of findings
        
        Returns:
            Dict: Compliance summary
        """
        enriched = self.enrich_findings(findings)
        
        # Collect all mappings
        owasp_categories = set()
        cwe_ids = set()
        pci_requirements = set()
        hipaa_controls = set()
        
        for finding in enriched:
            compliance = finding.get('compliance', {})
            
            # OWASP
            owasp = compliance.get('owasp', {})
            if owasp.get('id'):
                owasp_categories.add(owasp['id'])
            
            # CWE
            cwe_ids.update(compliance.get('cwe_ids', []))
            
            # PCI-DSS
            pci_requirements.update(compliance.get('pci_dss', []))
            
            # HIPAA
            hipaa_controls.update(compliance.get('hipaa', []))
        
        return {
            'owasp_top10': {
                'categories_affected': sorted(list(owasp_categories)),
                'count': len(owasp_categories)
            },
            'cwe': {
                'weaknesses_found': sorted(list(cwe_ids)),
                'count': len(cwe_ids)
            },
            'pci_dss': {
                'requirements_violated': sorted(list(pci_requirements)),
                'count': len(pci_requirements)
            },
            'hipaa': {
                'controls_affected': sorted(list(hipaa_controls)),
                'count': len(hipaa_controls)
            }
        }
    
    def _get_default_owasp_mappings(self) -> Dict:
        """Get default OWASP Top 10 mappings."""
        return {
            'sql_injection': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'SQL Injection allows attackers to interfere with database queries'
            },
            'xss_reflected': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'Cross-Site Scripting (XSS) - Reflected'
            },
            'xss_stored': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'Cross-Site Scripting (XSS) - Stored'
            },
            'xss_dom': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'Cross-Site Scripting (XSS) - DOM-based'
            },
            'broken_access_control': {
                'id': 'A01:2021',
                'category': 'Broken Access Control',
                'description': 'Access control enforces policy preventing users from acting outside intended permissions'
            },
            'broken_authentication': {
                'id': 'A07:2021',
                'category': 'Identification and Authentication Failures',
                'description': 'Authentication and session management issues'
            },
            'sensitive_data_exposure': {
                'id': 'A02:2021',
                'category': 'Cryptographic Failures',
                'description': 'Sensitive data exposure through inadequate protection'
            },
            'xxe': {
                'id': 'A05:2021',
                'category': 'Security Misconfiguration',
                'description': 'XML External Entity (XXE) injection'
            },
            'security_misconfiguration': {
                'id': 'A05:2021',
                'category': 'Security Misconfiguration',
                'description': 'Security misconfiguration in headers, CORS, etc.'
            },
            'cors_misconfiguration': {
                'id': 'A05:2021',
                'category': 'Security Misconfiguration',
                'description': 'CORS misconfiguration allowing unauthorized access'
            },
            'insecure_deserialization': {
                'id': 'A08:2021',
                'category': 'Software and Data Integrity Failures',
                'description': 'Insecure deserialization can lead to remote code execution'
            },
            'ssrf': {
                'id': 'A10:2021',
                'category': 'Server-Side Request Forgery (SSRF)',
                'description': 'SSRF allows attackers to force the server to make requests'
            },
            'path_traversal': {
                'id': 'A01:2021',
                'category': 'Broken Access Control',
                'description': 'Path traversal / LFI / RFI allows unauthorized file access'
            },
            'command_injection': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'OS Command Injection allows executing system commands'
            },
            'ldap_injection': {
                'id': 'A03:2021',
                'category': 'Injection',
                'description': 'LDAP Injection allows manipulating LDAP queries'
            },
            'unrestricted_file_upload': {
                'id': 'A04:2021',
                'category': 'Insecure Design',
                'description': 'Unrestricted file upload can lead to code execution'
            },
            'csrf': {
                'id': 'A01:2021',
                'category': 'Broken Access Control',
                'description': 'Cross-Site Request Forgery forces users to perform unwanted actions'
            },
            'mass_assignment': {
                'id': 'A04:2021',
                'category': 'Insecure Design',
                'description': 'Mass Assignment allows modifying object properties not intended to be changed'
            },
            'open_redirect': {
                'id': 'A01:2021',
                'category': 'Broken Access Control',
                'description': 'Open Redirect can be used for phishing attacks'
            }
        }
    
    def _get_default_cwe_mappings(self) -> Dict:
        """Get default CWE mappings."""
        return {
            'sql_injection': {'cwe_ids': [89]},
            'xss_reflected': {'cwe_ids': [79]},
            'xss_stored': {'cwe_ids': [79, 80]},
            'xss_dom': {'cwe_ids': [79, 85]},
            'broken_access_control': {'cwe_ids': [639, 284, 285]},
            'broken_authentication': {'cwe_ids': [287, 306, 307]},
            'sensitive_data_exposure': {'cwe_ids': [311, 312, 319, 326, 327]},
            'xxe': {'cwe_ids': [611]},
            'security_misconfiguration': {'cwe_ids': [16, 2]},
            'cors_misconfiguration': {'cwe_ids': [942, 346]},
            'insecure_deserialization': {'cwe_ids': [502]},
            'ssrf': {'cwe_ids': [918]},
            'path_traversal': {'cwe_ids': [22, 73]},
            'command_injection': {'cwe_ids': [78]},
            'ldap_injection': {'cwe_ids': [90]},
            'unrestricted_file_upload': {'cwe_ids': [434]},
            'csrf': {'cwe_ids': [352]},
            'mass_assignment': {'cwe_ids': [915]},
            'open_redirect': {'cwe_ids': [601]}
        }
    
    def _get_default_pci_mappings(self) -> Dict:
        """Get default PCI-DSS v4.0 mappings."""
        return {
            'sql_injection': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'xss_reflected': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'xss_stored': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'xss_dom': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'broken_access_control': {'requirements': ['7.2.1', '7.2.2', '7.3.1']},
            'broken_authentication': {'requirements': ['8.2.1', '8.2.3', '8.3.1']},
            'sensitive_data_exposure': {'requirements': ['3.1.1', '3.2.1', '4.2.1']},
            'xxe': {'requirements': ['6.2.4', '6.3.2']},
            'security_misconfiguration': {'requirements': ['2.2.1', '2.2.2', '6.2.4']},
            'cors_misconfiguration': {'requirements': ['2.2.1', '6.2.4']},
            'insecure_deserialization': {'requirements': ['6.2.4', '6.3.2']},
            'ssrf': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'path_traversal': {'requirements': ['6.2.4', '7.2.1']},
            'command_injection': {'requirements': ['6.2.4', '6.3.2', '11.6.1']},
            'ldap_injection': {'requirements': ['6.2.4', '6.3.2']},
            'unrestricted_file_upload': {'requirements': ['6.2.4', '6.3.2']},
            'csrf': {'requirements': ['6.2.4', '6.3.2']},
            'mass_assignment': {'requirements': ['6.2.4', '7.2.1']},
            'open_redirect': {'requirements': ['6.2.4', '6.3.2']}
        }
    
    def _get_default_hipaa_mappings(self) -> Dict:
        """Get default HIPAA Security Rule mappings."""
        return {
            'sql_injection': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'xss_reflected': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'xss_stored': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'xss_dom': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'broken_access_control': {'controls': ['§164.308(a)(3)', '§164.308(a)(4)', '§164.312(a)(1)']},
            'broken_authentication': {'controls': ['§164.308(a)(5)(ii)(D)', '§164.312(d)']},
            'sensitive_data_exposure': {'controls': ['§164.312(a)(2)(iv)', '§164.312(e)(2)(ii)']},
            'xxe': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'security_misconfiguration': {'controls': ['§164.308(a)(1)(ii)(B)', '§164.312(a)(1)']},
            'cors_misconfiguration': {'controls': ['§164.312(a)(1)', '§164.312(e)(1)']},
            'insecure_deserialization': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'ssrf': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'path_traversal': {'controls': ['§164.308(a)(3)', '§164.312(a)(1)']},
            'command_injection': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'ldap_injection': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'unrestricted_file_upload': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'csrf': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']},
            'mass_assignment': {'controls': ['§164.308(a)(3)', '§164.312(a)(1)']},
            'open_redirect': {'controls': ['§164.308(a)(1)(ii)(D)', '§164.312(a)(1)']}
        }
    
    def export_mappings(self, output_dir: str):
        """Export all mappings to YAML files.
        
        Args:
            output_dir: Directory to export mappings to
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export OWASP
        with open(output_path / 'owasp_top10.yaml', 'w') as f:
            yaml.dump(self.owasp_mappings, f, default_flow_style=False, sort_keys=False)
        
        # Export CWE
        with open(output_path / 'cwe_mappings.yaml', 'w') as f:
            yaml.dump(self.cwe_mappings, f, default_flow_style=False, sort_keys=False)
        
        # Export PCI-DSS
        with open(output_path / 'pci_dss.yaml', 'w') as f:
            yaml.dump(self.pci_mappings, f, default_flow_style=False, sort_keys=False)
        
        # Export HIPAA
        with open(output_path / 'hipaa.yaml', 'w') as f:
            yaml.dump(self.hipaa_mappings, f, default_flow_style=False, sort_keys=False)
