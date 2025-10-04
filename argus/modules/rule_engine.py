"""Configurable rule engine - YAML/JSON-based module prioritization.

Replaces hardcoded if/elif logic with flexible, user-customizable rules.
Rules support conditions, weighted scoring, and dynamic module selection.

Example rule file (rules.yaml):
```yaml
rules:
  - name: URL Parameters
    condition:
      param_name:
        contains: [url, redirect, return, next, dest]
    modules: [open_redirect, ssrf, xss]
    weight: 100
    
  - name: ID Parameters
    condition:
      param_name:
        in: [id, userid, user_id]
    modules: [sqli, idor, xss]
    weight: 90
```
"""
from typing import Dict, List, Any, Optional
import yaml
import json
import re
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Rule:
    """Represents a single prioritization rule."""
    name: str
    condition: Dict[str, Any]
    modules: List[str]
    weight: int = 50
    enabled: bool = True
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def matches(self, parameter: Dict, context: Dict) -> bool:
        """Check if rule matches the given parameter and context.
        
        Args:
            parameter: Parameter dict with name, value, location
            context: Context dict with url, method, all_params
        
        Returns:
            bool: True if rule matches
        """
        if not self.enabled:
            return False
        
        # Evaluate each condition
        for field_name, criteria in self.condition.items():
            if field_name == 'param_name':
                param_name = (parameter.get('name') or '').lower()
                if not self._evaluate_criteria(param_name, criteria):
                    return False
            
            elif field_name == 'param_location':
                param_location = parameter.get('location', '')
                if not self._evaluate_criteria(param_location, criteria):
                    return False
            
            elif field_name == 'url_pattern':
                url = context.get('url', '').lower()
                if not self._evaluate_criteria(url, criteria):
                    return False
            
            elif field_name == 'method':
                method = context.get('method', 'GET').upper()
                if not self._evaluate_criteria(method, criteria):
                    return False
            
            elif field_name == 'has_params':
                all_params = context.get('all_params', [])
                param_names = [p.get('name', '').lower() for p in all_params]
                if not self._evaluate_criteria(param_names, criteria):
                    return False
            
            else:
                # Unknown field - skip
                continue
        
        return True
    
    def _evaluate_criteria(self, value: Any, criteria: Any) -> bool:
        """Evaluate a single criteria.
        
        Args:
            value: Value to test
            criteria: Criteria specification
        
        Returns:
            bool: True if criteria matches
        """
        if isinstance(criteria, dict):
            # Complex criteria with operators
            for operator, operand in criteria.items():
                if operator == 'contains':
                    # Check if value contains any of the keywords
                    if isinstance(operand, list):
                        return any(keyword in str(value) for keyword in operand)
                    else:
                        return operand in str(value)
                
                elif operator == 'in':
                    # Check if value is in list
                    if isinstance(operand, list):
                        return str(value) in operand
                    else:
                        return str(value) == operand
                
                elif operator == 'equals':
                    return str(value) == str(operand)
                
                elif operator == 'regex':
                    return bool(re.search(operand, str(value)))
                
                elif operator == 'startswith':
                    return str(value).startswith(str(operand))
                
                elif operator == 'endswith':
                    return str(value).endswith(str(operand))
                
                elif operator == 'not':
                    # Negation
                    return not self._evaluate_criteria(value, operand)
                
                elif operator == 'any':
                    # Match any of the sub-criteria
                    if isinstance(operand, list):
                        return any(self._evaluate_criteria(value, op) for op in operand)
                
                elif operator == 'all':
                    # Match all of the sub-criteria
                    if isinstance(operand, list):
                        return all(self._evaluate_criteria(value, op) for op in operand)
        
        else:
            # Simple equality check
            return str(value) == str(criteria)
        
        return False


class RuleEngine:
    """Rule engine for configurable module prioritization."""
    
    def __init__(self, rules_path: Optional[str] = None):
        """Initialize rule engine.
        
        Args:
            rules_path: Path to rules file (YAML or JSON)
        """
        self.rules: List[Rule] = []
        self.default_rules_loaded = False
        
        if rules_path:
            self.load_rules(rules_path)
        else:
            self.load_default_rules()
    
    def load_rules(self, path: str):
        """Load rules from YAML or JSON file.
        
        Args:
            path: Path to rules file
        """
        rule_file = Path(path)
        
        if not rule_file.exists():
            raise FileNotFoundError(f"Rules file not found: {path}")
        
        # Load based on extension
        content = rule_file.read_text()
        
        if path.endswith('.yaml') or path.endswith('.yml'):
            data = yaml.safe_load(content)
        elif path.endswith('.json'):
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported rules file format: {path}")
        
        # Parse rules
        self.rules = []
        for rule_dict in data.get('rules', []):
            rule = Rule(
                name=rule_dict['name'],
                condition=rule_dict['condition'],
                modules=rule_dict['modules'],
                weight=rule_dict.get('weight', 50),
                enabled=rule_dict.get('enabled', True),
                description=rule_dict.get('description', ''),
                tags=rule_dict.get('tags', [])
            )
            self.rules.append(rule)
        
        # Sort by weight (descending)
        self.rules.sort(key=lambda r: r.weight, reverse=True)
    
    def load_default_rules(self):
        """Load built-in default rules."""
        default_rules = [
            {
                'name': 'URL/Redirect Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['url', 'redirect', 'return', 'next', 'continue', 
                                   'dest', 'destination', 'redir', 'link', 'goto']
                    }
                },
                'modules': ['open_redirect', 'ssrf', 'xss'],
                'weight': 100,
                'description': 'Parameters that handle URLs are prone to SSRF and open redirects',
                'tags': ['redirect', 'ssrf']
            },
            {
                'name': 'File/Path Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['file', 'path', 'dir', 'folder', 'upload', 
                                   'document', 'download', 'template']
                    }
                },
                'modules': ['path_traversal', 'lfi_rfi', 'command_injection', 'xss'],
                'weight': 95,
                'description': 'File parameters are vulnerable to path traversal and LFI',
                'tags': ['file', 'traversal']
            },
            {
                'name': 'Command/System Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['cmd', 'command', 'exec', 'system', 'shell', 
                                   'ping', 'host', 'ip']
                    }
                },
                'modules': ['command_injection', 'sqli', 'xss'],
                'weight': 95,
                'description': 'Command parameters are prime targets for command injection',
                'tags': ['rce', 'command']
            },
            {
                'name': 'Authentication Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['user', 'pass', 'login', 'auth', 'email', 
                                   'username', 'password', 'token']
                    }
                },
                'modules': ['sqli', 'xss', 'csrf'],
                'weight': 90,
                'description': 'Auth parameters are critical and often targeted',
                'tags': ['auth', 'credential']
            },
            {
                'name': 'API Endpoints',
                'condition': {
                    'url_pattern': {
                        'contains': ['/api/', 'api.']
                    }
                },
                'modules': ['api_vulnerabilities', 'sqli', 'xss', 'idor'],
                'weight': 85,
                'description': 'API endpoints have unique vulnerabilities',
                'tags': ['api', 'rest']
            },
            {
                'name': 'Search Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['search', 'query', 'q', 'keyword', 'term', 'find']
                    }
                },
                'modules': ['xss', 'sqli'],
                'weight': 80,
                'description': 'Search inputs are often reflected in responses',
                'tags': ['search', 'input']
            },
            {
                'name': 'Data/Object Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['data', 'object', 'payload', 'serialized', 
                                   'json', 'xml', 'content']
                    }
                },
                'modules': ['insecure_deserialization', 'xss', 'sqli'],
                'weight': 75,
                'description': 'Serialized data can lead to deserialization attacks',
                'tags': ['serialization', 'data']
            },
            {
                'name': 'ID Parameters',
                'condition': {
                    'param_name': {
                        'in': ['id', 'userid', 'user_id', 'item_id', 'product_id', 
                              'order_id', 'account_id', 'object_id']
                    }
                },
                'modules': ['sqli', 'idor', 'xss'],
                'weight': 70,
                'description': 'ID parameters are common SQLi and IDOR targets',
                'tags': ['id', 'database']
            },
            {
                'name': 'POST/PUT/PATCH Requests',
                'condition': {
                    'method': {
                        'in': ['POST', 'PUT', 'PATCH', 'DELETE']
                    }
                },
                'modules': ['csrf', 'xss', 'sqli'],
                'weight': 65,
                'description': 'State-changing requests need CSRF protection',
                'tags': ['csrf', 'state-change']
            },
            {
                'name': 'Callback Parameters',
                'condition': {
                    'param_name': {
                        'contains': ['callback', 'jsonp', 'cb', 'return_to']
                    }
                },
                'modules': ['xss', 'open_redirect'],
                'weight': 60,
                'description': 'Callback parameters can lead to XSS',
                'tags': ['callback', 'jsonp']
            },
            {
                'name': 'URL-Level Checks',
                'condition': {
                    'param_name': {
                        'equals': None
                    }
                },
                'modules': ['insecure_headers', 'cors'],
                'weight': 50,
                'description': 'Check headers and CORS on all endpoints',
                'tags': ['headers', 'config']
            }
        ]
        
        # Convert to Rule objects
        for rule_dict in default_rules:
            rule = Rule(
                name=rule_dict['name'],
                condition=rule_dict['condition'],
                modules=rule_dict['modules'],
                weight=rule_dict.get('weight', 50),
                enabled=True,
                description=rule_dict.get('description', ''),
                tags=rule_dict.get('tags', [])
            )
            self.rules.append(rule)
        
        self.default_rules_loaded = True
    
    def prioritize_modules(
        self,
        parameter: Dict,
        context: Dict,
        available_modules: List[str]
    ) -> List[str]:
        """Prioritize modules for a parameter using rules.
        
        Args:
            parameter: Parameter dict
            context: Context dict
            available_modules: List of available module names
        
        Returns:
            List of module names sorted by priority
        """
        # Find matching rules
        matched_rules = []
        for rule in self.rules:
            if rule.matches(parameter, context):
                matched_rules.append(rule)
        
        # Build weighted priority map
        module_scores = {}
        for rule in matched_rules:
            for module_name in rule.modules:
                if module_name in available_modules:
                    module_scores[module_name] = max(
                        module_scores.get(module_name, 0),
                        rule.weight
                    )
        
        # Sort by score (descending)
        prioritized = sorted(
            module_scores.keys(),
            key=lambda m: module_scores[m],
            reverse=True
        )
        
        # Add remaining modules (not matched by any rule)
        for module_name in available_modules:
            if module_name not in prioritized:
                prioritized.append(module_name)
        
        return prioritized
    
    def export_rules(self, path: str, format: str = 'yaml'):
        """Export current rules to file.
        
        Args:
            path: Output file path
            format: Output format ('yaml' or 'json')
        """
        rules_data = {
            'rules': [
                {
                    'name': rule.name,
                    'condition': rule.condition,
                    'modules': rule.modules,
                    'weight': rule.weight,
                    'enabled': rule.enabled,
                    'description': rule.description,
                    'tags': rule.tags
                }
                for rule in self.rules
            ]
        }
        
        output_file = Path(path)
        
        if format == 'yaml':
            content = yaml.dump(rules_data, default_flow_style=False, sort_keys=False)
        elif format == 'json':
            content = json.dumps(rules_data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        output_file.write_text(content)
    
    def add_rule(self, rule: Rule):
        """Add a new rule.
        
        Args:
            rule: Rule to add
        """
        self.rules.append(rule)
        # Re-sort by weight
        self.rules.sort(key=lambda r: r.weight, reverse=True)
    
    def remove_rule(self, rule_name: str):
        """Remove a rule by name.
        
        Args:
            rule_name: Name of rule to remove
        """
        self.rules = [r for r in self.rules if r.name != rule_name]
    
    def get_rule(self, rule_name: str) -> Optional[Rule]:
        """Get a rule by name.
        
        Args:
            rule_name: Rule name
        
        Returns:
            Rule object or None
        """
        for rule in self.rules:
            if rule.name == rule_name:
                return rule
        return None
    
    def list_rules(self, tag: Optional[str] = None, enabled_only: bool = True) -> List[Rule]:
        """List all rules, optionally filtered.
        
        Args:
            tag: Filter by tag
            enabled_only: Only return enabled rules
        
        Returns:
            List of rules
        """
        rules = self.rules
        
        if enabled_only:
            rules = [r for r in rules if r.enabled]
        
        if tag:
            rules = [r for r in rules if tag in r.tags]
        
        return rules


def create_default_rules_file(output_path: str = 'rules.yaml'):
    """Create a default rules file for user customization.
    
    Args:
        output_path: Where to save the rules file
    """
    engine = RuleEngine()
    engine.export_rules(output_path, format='yaml')
    print(f"✅ Default rules exported to: {output_path}")
    print("You can now customize these rules to fit your needs!")
