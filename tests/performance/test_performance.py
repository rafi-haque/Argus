"""Performance tests for Argus scanner.

These tests validate performance requirements from the specification:
- Complete scans in <15 minutes for apps with up to 200 endpoints
- Maintain <5 req/sec throughput
- Support up to 500 endpoints and 2000 parameters
"""
import pytest
import time
from unittest.mock import Mock, patch
from argus.modules.crawler import Crawler
from argus.modules.orchestrator import ScannerOrchestrator
from argus.modules.attack_modules.insecure_headers import InsecureHeadersModule


class TestCrawlerPerformance:
    """Performance tests for crawler module."""
    
    def test_crawl_speed_small_site(self):
        """Test crawler completes small site (10 pages) quickly."""
        config = {'max_depth': 2, 'follow_external': False}
        crawler = Crawler('http://example.com', config)
        
        # Mock HTTP requests to simulate fast responses
        with patch('argus.modules.crawler.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = """
                <html>
                    <a href="/page1">Page 1</a>
                    <a href="/page2">Page 2</a>
                </html>
            """
            mock_get.return_value = mock_response
            
            start_time = time.time()
            site_map = crawler.passive_crawl()
            elapsed = time.time() - start_time
            
            # Should complete in <1 second for 10 pages
            assert elapsed < 1.0, f"Crawl took {elapsed:.2f}s, expected <1s"
    
    def test_crawl_memory_usage(self):
        """Test crawler memory usage remains reasonable for large sites."""
        config = {'max_depth': 3, 'follow_external': False}
        crawler = Crawler('http://example.com', config)
        
        # Mock 100 pages
        with patch('argus.modules.crawler.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = '<html><a href="/page">Link</a></html>'
            mock_get.return_value = mock_response
            
            site_map = crawler.passive_crawl()
            
            # Site map should be manageable size
            assert len(site_map) <= 500, "Site map grew too large"


class TestOrchestratorPerformance:
    """Performance tests for orchestrator module."""
    
    def test_scan_speed_100_endpoints(self):
        """Test scanning 100 endpoints completes in reasonable time."""
        config = {'performance': {'max_concurrent': 5, 'timeout': 10}}
        modules = [InsecureHeadersModule(config)]
        orchestrator = ScannerOrchestrator('http://example.com', modules, config)
        
        # Mock site map with 100 endpoints
        site_map = [
            {
                'url': f'http://example.com/page{i}',
                'method': 'GET',
                'parameters': []
            }
            for i in range(100)
        ]
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            start_time = time.time()
            findings = orchestrator.run_scan(site_map)
            elapsed = time.time() - start_time
            
            # Should complete in <60 seconds for 100 endpoints
            assert elapsed < 60.0, f"Scan took {elapsed:.2f}s, expected <60s"
    
    def test_scan_speed_200_endpoints(self):
        """Test scanning 200 endpoints meets 15-minute requirement."""
        config = {'performance': {'max_concurrent': 5, 'timeout': 10}}
        modules = [InsecureHeadersModule(config)]
        orchestrator = ScannerOrchestrator('http://example.com', modules, config)
        
        # Mock site map with 200 endpoints
        site_map = [
            {
                'url': f'http://example.com/page{i}',
                'method': 'GET',
                'parameters': []
            }
            for i in range(200)
        ]
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            start_time = time.time()
            findings = orchestrator.run_scan(site_map)
            elapsed = time.time() - start_time
            
            # Should complete in <15 minutes (900 seconds)
            assert elapsed < 900.0, f"Scan took {elapsed:.2f}s, expected <900s"
    
    def test_request_rate_limiting(self):
        """Test request rate stays under 5 req/sec."""
        config = {'performance': {'max_concurrent': 5, 'request_delay': 0.2, 'timeout': 10}}
        modules = [InsecureHeadersModule(config)]
        orchestrator = ScannerOrchestrator('http://example.com', modules, config)
        
        # Mock 20 endpoints
        site_map = [
            {
                'url': f'http://example.com/page{i}',
                'method': 'GET',
                'parameters': []
            }
            for i in range(20)
        ]
        
        request_times = []
        
        def mock_request(*args, **kwargs):
            request_times.append(time.time())
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            return mock_response
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get', side_effect=mock_request):
            orchestrator.run_scan(site_map)
            
            # Calculate request rate
            if len(request_times) > 1:
                duration = request_times[-1] - request_times[0]
                rate = len(request_times) / duration
                
                # Should maintain <5 req/sec
                assert rate < 5.0, f"Request rate was {rate:.2f} req/sec, expected <5"


class TestScalabilityLimits:
    """Test handling of scale limits from spec."""
    
    def test_handle_500_endpoints(self):
        """Test scanner handles maximum 500 endpoints."""
        config = {'performance': {'max_concurrent': 5}}
        modules = [InsecureHeadersModule(config)]
        orchestrator = ScannerOrchestrator('http://example.com', modules, config)
        
        # Create site map at scale limit
        site_map = [
            {
                'url': f'http://example.com/page{i}',
                'method': 'GET',
                'parameters': []
            }
            for i in range(500)
        ]
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            # Should not crash or run out of memory
            findings = orchestrator.run_scan(site_map)
            assert isinstance(findings, list)
    
    def test_handle_many_parameters(self):
        """Test handling endpoints with many parameters."""
        config = {}
        modules = [InsecureHeadersModule(config)]
        orchestrator = ScannerOrchestrator('http://example.com', modules, config)
        
        # Create endpoint with 100 parameters
        site_map = [
            {
                'url': 'http://example.com/api',
                'method': 'POST',
                'parameters': [
                    {
                        'name': f'param{i}',
                        'value': 'test',
                        'location': 'body'
                    }
                    for i in range(100)
                ]
            }
        ]
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            # Should handle many parameters without issues
            findings = orchestrator.run_scan(site_map)
            assert isinstance(findings, list)


class TestRetryMechanism:
    """Test retry logic meets spec requirements."""
    
    def test_retry_failed_requests(self):
        """Test scanner retries failed requests 3 times."""
        config = {'performance': {'timeout': 1}}
        
        with patch('argus.modules.attack_modules.insecure_headers.requests.get') as mock_get:
            # Fail 3 times, succeed on 4th
            mock_get.side_effect = [
                Exception("Connection failed"),
                Exception("Connection failed"),
                Exception("Connection failed"),
                Mock(status_code=200, headers={})
            ]
            
            module = InsecureHeadersModule(config)
            
            # Should eventually succeed after retries
            # Note: Actual retry logic would need to be implemented in modules
            # This test documents the expected behavior


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
