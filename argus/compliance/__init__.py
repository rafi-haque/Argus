"""Compliance mapping module for Argus.

Provides mappings between vulnerabilities and compliance standards:
- OWASP Top 10 2021
- CWE (Common Weakness Enumeration)
- PCI-DSS v4.0
- HIPAA Security Rule
"""

from .mappings import ComplianceMapper, ComplianceMapping

__all__ = ['ComplianceMapper', 'ComplianceMapping']
