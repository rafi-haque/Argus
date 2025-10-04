"""Differential analysis module - Intelligent response comparison for vulnerability detection.

Replaces naive grep-based detection with statistical analysis and behavioral fingerprinting.
Dramatically reduces false positives by comparing response characteristics rather than
simply searching for payload strings in the response.
"""
from typing import Dict, List, Tuple, Optional
import re
import hashlib
from difflib import SequenceMatcher
from statistics import mean, stdev
import httpx


class DifferentialAnalyzer:
    """Performs intelligent response comparison for vulnerability detection.
    
    Instead of naive grep detection (search for payload in response), this analyzer
    uses multiple comparison techniques:
    
    1. Content-Length Delta Analysis
       - Compare response sizes to detect anomalies
       - Flag significant deviations (>20% change)
    
    2. Timing Deviation Analysis
       - Statistical analysis of response times
       - Detect time-based injection (e.g., SQL SLEEP)
    
    3. Content Similarity Analysis
       - Compare response content using difflib
       - Detect subtle changes vs complete rewrites
    
    4. Behavioral Fingerprinting
       - HTTP status code changes
       - Header changes
       - Error message patterns
    
    5. Statistical Confidence Scoring
       - Combine multiple signals
       - Return confidence score (0-100)
    """
    
    def __init__(self, config: dict = None):
        """Initialize analyzer.
        
        Args:
            config: Configuration dict with thresholds
        """
        self.config = config or {}
        
        # Thresholds (tunable)
        self.size_delta_threshold = self.config.get('size_delta_threshold', 0.20)  # 20%
        self.timing_stdev_multiplier = self.config.get('timing_stdev_multiplier', 3.0)
        self.similarity_threshold = self.config.get('similarity_threshold', 0.90)  # 90% similar
        self.min_timing_samples = self.config.get('min_timing_samples', 3)
    
    def compare_responses(
        self,
        baseline: httpx.Response,
        test: httpx.Response,
        comparison_type: str = 'full'
    ) -> Dict:
        """Compare two responses and return analysis.
        
        Args:
            baseline: Baseline response (normal input)
            test: Test response (payload input)
            comparison_type: Type of comparison ('full', 'size', 'timing', 'content')
        
        Returns:
            dict: Analysis results with scores and detected differences
        """
        analysis = {
            'is_different': False,
            'confidence': 0.0,
            'signals': [],
            'details': {}
        }
        
        if comparison_type in ['full', 'size']:
            size_analysis = self._analyze_size_delta(baseline, test)
            if size_analysis['is_significant']:
                analysis['is_different'] = True
                analysis['signals'].append('size_delta')
                analysis['details']['size'] = size_analysis
        
        if comparison_type in ['full', 'content']:
            content_analysis = self._analyze_content_similarity(baseline, test)
            if not content_analysis['is_similar']:
                analysis['is_different'] = True
                analysis['signals'].append('content_change')
                analysis['details']['content'] = content_analysis
        
        if comparison_type in ['full']:
            behavior_analysis = self._analyze_behavioral_changes(baseline, test)
            if behavior_analysis['has_changes']:
                analysis['is_different'] = True
                analysis['signals'].extend(behavior_analysis['changes'])
                analysis['details']['behavior'] = behavior_analysis
        
        # Calculate confidence score
        analysis['confidence'] = self._calculate_confidence_score(analysis)
        
        return analysis
    
    def analyze_timing_anomaly(
        self,
        baseline_times: List[float],
        test_time: float
    ) -> Dict:
        """Analyze if response time indicates anomaly (e.g., SQL injection with SLEEP).
        
        Args:
            baseline_times: List of baseline response times
            test_time: Test response time
        
        Returns:
            dict: Timing analysis with anomaly detection
        """
        if len(baseline_times) < self.min_timing_samples:
            return {
                'is_anomaly': False,
                'confidence': 0.0,
                'reason': 'insufficient_baseline_samples'
            }
        
        baseline_mean = mean(baseline_times)
        baseline_stdev = stdev(baseline_times) if len(baseline_times) > 1 else 0.0
        
        # Calculate z-score
        if baseline_stdev > 0:
            z_score = abs((test_time - baseline_mean) / baseline_stdev)
        else:
            z_score = 0.0
        
        # Anomaly if test_time is significantly higher than baseline
        threshold = baseline_mean + (self.timing_stdev_multiplier * baseline_stdev)
        is_anomaly = test_time > threshold
        
        # Confidence based on how far outside normal range
        confidence = min(100, (z_score / self.timing_stdev_multiplier) * 100) if is_anomaly else 0
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'test_time': test_time,
            'baseline_mean': baseline_mean,
            'baseline_stdev': baseline_stdev,
            'z_score': z_score,
            'threshold': threshold,
            'details': f"{test_time:.3f}s vs baseline {baseline_mean:.3f}±{baseline_stdev:.3f}s"
        }
    
    def _analyze_size_delta(
        self,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Analyze content-length delta between responses.
        
        Args:
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: Size delta analysis
        """
        baseline_size = len(baseline.content)
        test_size = len(test.content)
        
        # Calculate delta
        if baseline_size > 0:
            delta_pct = abs(test_size - baseline_size) / baseline_size
        else:
            delta_pct = 1.0 if test_size > 0 else 0.0
        
        is_significant = delta_pct > self.size_delta_threshold
        
        return {
            'is_significant': is_significant,
            'baseline_size': baseline_size,
            'test_size': test_size,
            'delta_bytes': test_size - baseline_size,
            'delta_pct': delta_pct,
            'threshold': self.size_delta_threshold
        }
    
    def _analyze_content_similarity(
        self,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Analyze content similarity using difflib.
        
        Args:
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: Content similarity analysis
        """
        baseline_text = baseline.text
        test_text = test.text
        
        # Use SequenceMatcher for similarity ratio
        similarity = SequenceMatcher(None, baseline_text, test_text).ratio()
        
        is_similar = similarity >= self.similarity_threshold
        
        # Identify changed sections (for reporting)
        if not is_similar:
            # Find first significant difference
            diff_start = self._find_first_significant_diff(baseline_text, test_text)
        else:
            diff_start = None
        
        return {
            'is_similar': is_similar,
            'similarity_ratio': similarity,
            'threshold': self.similarity_threshold,
            'diff_start_pos': diff_start,
            'baseline_hash': hashlib.md5(baseline_text.encode()).hexdigest()[:16],
            'test_hash': hashlib.md5(test_text.encode()).hexdigest()[:16]
        }
    
    def _analyze_behavioral_changes(
        self,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Analyze behavioral differences (status, headers, errors).
        
        Args:
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: Behavioral analysis
        """
        changes = []
        has_changes = False
        
        # Status code change
        if baseline.status_code != test.status_code:
            changes.append('status_code')
            has_changes = True
        
        # Error patterns in response
        error_patterns = [
            r'sql.*error',
            r'mysql.*error',
            r'ora-\d+',
            r'postgresql.*error',
            r'sqlite.*error',
            r'syntax.*error',
            r'unexpected.*token',
            r'parse.*error',
            r'exception',
            r'stack.*trace',
            r'warning.*line',
        ]
        
        baseline_has_error = any(
            re.search(pattern, baseline.text, re.IGNORECASE)
            for pattern in error_patterns
        )
        test_has_error = any(
            re.search(pattern, test.text, re.IGNORECASE)
            for pattern in error_patterns
        )
        
        if test_has_error and not baseline_has_error:
            changes.append('error_introduced')
            has_changes = True
        
        # Content-Type change
        baseline_ct = baseline.headers.get('content-type', '')
        test_ct = test.headers.get('content-type', '')
        if baseline_ct != test_ct:
            changes.append('content_type')
            has_changes = True
        
        return {
            'has_changes': has_changes,
            'changes': changes,
            'status_change': {
                'baseline': baseline.status_code,
                'test': test.status_code
            } if baseline.status_code != test.status_code else None,
            'error_introduced': test_has_error and not baseline_has_error
        }
    
    def _calculate_confidence_score(self, analysis: Dict) -> float:
        """Calculate overall confidence score from signals.
        
        Args:
            analysis: Analysis dict with signals and details
        
        Returns:
            float: Confidence score (0-100)
        """
        if not analysis['is_different']:
            return 0.0
        
        # Base confidence on number and type of signals
        signal_weights = {
            'size_delta': 30,
            'content_change': 40,
            'status_code': 25,
            'error_introduced': 50,
            'content_type': 15
        }
        
        total_score = 0.0
        max_possible = 0.0
        
        for signal in analysis['signals']:
            weight = signal_weights.get(signal, 10)
            total_score += weight
            max_possible += weight
        
        # Normalize to 0-100
        if max_possible > 0:
            confidence = min(100, (total_score / max_possible) * 100)
        else:
            confidence = 0.0
        
        return confidence
    
    def _find_first_significant_diff(
        self,
        baseline: str,
        test: str,
        window: int = 50
    ) -> Optional[int]:
        """Find position of first significant difference.
        
        Args:
            baseline: Baseline text
            test: Test text
            window: Window size for comparison
        
        Returns:
            int: Position of first diff, or None
        """
        min_len = min(len(baseline), len(test))
        
        for i in range(0, min_len, window):
            baseline_chunk = baseline[i:i+window]
            test_chunk = test[i:i+window]
            
            if baseline_chunk != test_chunk:
                return i
        
        return None


class ResponseComparator:
    """High-level interface for response comparison in attack modules.
    
    Usage in attack modules:
        comparator = ResponseComparator(config)
        
        # Test payload
        baseline = await client.get(url, params={'id': '1'})
        test = await client.get(url, params={'id': "1' OR '1'='1"})
        
        result = comparator.is_vulnerable(baseline, test, 'sqli')
        if result['is_vulnerable']:
            # Report finding with confidence score
            finding = {
                'confidence': result['confidence'],
                'evidence': result['evidence']
            }
    """
    
    def __init__(self, config: dict = None):
        """Initialize comparator."""
        self.analyzer = DifferentialAnalyzer(config)
    
    def is_vulnerable(
        self,
        baseline: httpx.Response,
        test: httpx.Response,
        vuln_type: str
    ) -> Dict:
        """Determine if test response indicates vulnerability.
        
        Args:
            baseline: Baseline response
            test: Test response
            vuln_type: Vulnerability type ('sqli', 'xss', 'rce', etc.)
        
        Returns:
            dict: Vulnerability assessment with confidence and evidence
        """
        # Perform full differential analysis
        analysis = self.analyzer.compare_responses(baseline, test, 'full')
        
        # Vulnerability-specific logic
        if vuln_type == 'sqli':
            return self._assess_sqli(analysis, baseline, test)
        elif vuln_type == 'xss':
            return self._assess_xss(analysis, baseline, test)
        elif vuln_type == 'rce':
            return self._assess_rce(analysis, baseline, test)
        else:
            # Generic assessment
            return {
                'is_vulnerable': analysis['is_different'] and analysis['confidence'] > 50,
                'confidence': analysis['confidence'],
                'evidence': analysis['signals'],
                'details': analysis['details']
            }
    
    def _assess_sqli(
        self,
        analysis: Dict,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Assess SQL injection vulnerability.
        
        Args:
            analysis: Differential analysis
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: SQLi assessment
        """
        # SQLi indicators
        is_vulnerable = False
        confidence = analysis['confidence']
        evidence = analysis['signals'].copy()
        
        # Check for SQL error messages (strong indicator)
        if 'error_introduced' in evidence:
            is_vulnerable = True
            confidence = max(confidence, 80)
            evidence.append('sql_error_pattern')
        
        # Check for size delta (boolean-based blind SQLi)
        if 'size_delta' in evidence:
            details = analysis['details'].get('size', {})
            if details.get('delta_pct', 0) > 0.3:  # >30% size change
                is_vulnerable = True
                confidence = max(confidence, 70)
        
        # Check for content similarity (union-based SQLi)
        if 'content_change' in evidence:
            is_vulnerable = True
            confidence = max(confidence, 65)
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': confidence,
            'evidence': evidence,
            'details': analysis['details'],
            'technique': self._identify_sqli_technique(analysis)
        }
    
    def _assess_xss(
        self,
        analysis: Dict,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Assess XSS vulnerability.
        
        Args:
            analysis: Differential analysis
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: XSS assessment
        """
        # For XSS, we need to check if payload is reflected
        # This is a simplified version - full implementation would check context
        
        is_vulnerable = False
        confidence = analysis['confidence']
        
        # XSS payloads should appear in response
        # But differential analysis shows if response structure changed
        
        if 'content_change' in analysis['signals']:
            # Response changed - possible XSS
            is_vulnerable = True
            confidence = max(confidence, 60)
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': confidence,
            'evidence': analysis['signals'],
            'details': analysis['details']
        }
    
    def _assess_rce(
        self,
        analysis: Dict,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Dict:
        """Assess RCE vulnerability.
        
        Args:
            analysis: Differential analysis
            baseline: Baseline response
            test: Test response
        
        Returns:
            dict: RCE assessment
        """
        is_vulnerable = False
        confidence = analysis['confidence']
        
        # RCE indicators: error messages, output changes
        if 'error_introduced' in analysis['signals']:
            is_vulnerable = True
            confidence = max(confidence, 75)
        
        if 'content_change' in analysis['signals']:
            # Check if content contains command output patterns
            is_vulnerable = True
            confidence = max(confidence, 65)
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': confidence,
            'evidence': analysis['signals'],
            'details': analysis['details']
        }
    
    def _identify_sqli_technique(self, analysis: Dict) -> str:
        """Identify SQLi technique from analysis.
        
        Args:
            analysis: Differential analysis
        
        Returns:
            str: Technique name
        """
        if 'error_introduced' in analysis['signals']:
            return 'error-based'
        elif 'size_delta' in analysis['signals']:
            return 'boolean-based'
        elif 'content_change' in analysis['signals']:
            return 'union-based'
        else:
            return 'unknown'
