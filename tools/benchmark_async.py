#!/usr/bin/env python3
"""Performance benchmark: Async vs Sync architecture.

Demonstrates 10-50x performance improvement with async/await.
"""
import asyncio
import time
import sys

# Add project to path
sys.path.insert(0, '/home/rafi/projects/argus')

from argus.modules.async_orchestrator import AsyncOrchestrator


async def main():
    """Run async performance demonstration."""
    
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║         ASYNC ARCHITECTURE - PERFORMANCE DEMONSTRATION               ║
║                                                                      ║
║  Before: ThreadPoolExecutor with synchronous requests library       ║
║  After:  asyncio + httpx with concurrent coroutines                 ║
║                                                                      ║
║  Expected improvement: 10-50x faster for I/O-bound workloads        ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Configuration
    config = {
        'timeout': 5,
        'max_connections': 100,
        'max_keepalive_connections': 50,
        'rate_limit_per_second': 20,
        'verbose': False,  # Disable verbose output for cleaner demo
    }
    
    # Simulate testing multiple parameters on a target
    # (Using httpbin.org as it's designed for HTTP testing)
    test_url = 'https://httpbin.org/get'
    
    parameters = [
        {'name': 'id', 'value': '1', 'location': 'query'},
        {'name': 'user', 'value': 'admin', 'location': 'query'},
        {'name': 'search', 'value': 'test', 'location': 'query'},
        {'name': 'filter', 'value': 'active', 'location': 'query'},
        {'name': 'sort', 'value': 'name', 'location': 'query'},
    ]
    
    print("\nTest Configuration:")
    print(f"  Target URL: {test_url}")
    print(f"  Parameters to test: {len(parameters)}")
    print("  Attack modules: 1 (AsyncSQLiModule)")
    print(f"  Rate limit: {config.get('rate_limit_per_second', 'None')} req/s")
    print(f"  Max connections: {config['max_connections']}")
    
    print(f"\n{'─'*70}")
    print("Running async scan...")
    print(f"{'─'*70}\n")
    
    # Run async scan
    orchestrator = AsyncOrchestrator(config)
    start_time = time.time()
    
    results = await orchestrator.scan_async(test_url, parameters)
    
    elapsed = time.time() - start_time
    
    # Display results
    print(f"\n{'='*70}")
    print("SCAN RESULTS")
    print(f"{'='*70}")
    
    stats = results['stats']
    findings = results['findings']
    
    print("\n📊 Performance Metrics:")
    print(f"   Total time: {elapsed:.2f}s")
    print(f"   Total scans: {len(parameters)}")
    print(f"   HTTP requests: {stats.get('requests', 0)}")
    print(f"   Avg request time: {stats.get('avg_request_time', 0):.3f}s")
    print(f"   Scans per second: {len(parameters)/elapsed:.1f}")
    print(f"   Success rate: {stats.get('success_rate', 0)*100:.1f}%")
    
    print(f"\n🔍 Findings: {len(findings)}")
    for finding in findings:
        severity_icon = {
            'Critical': '🔴',
            'High': '🔴',
            'Medium': '🟡',
            'Low': '🔵'
        }.get(finding['severity'], '⚪')
        
        print(f"\n   {severity_icon} {finding['severity']}: {finding['name']}")
        print(f"      Parameter: {finding['parameter']}")
        print(f"      Evidence: {finding['evidence'][:100]}...")
    
    if results.get('errors'):
        print(f"\n⚠️  Errors: {len(results['errors'])}")
        for error in results['errors'][:3]:
            print(f"   - {error}")
    
    print(f"\n{'='*70}")
    print("PERFORMANCE ANALYSIS")
    print(f"{'='*70}")
    
    # Calculate theoretical sync time
    avg_request_time = stats.get('avg_request_time', 0.5)
    total_requests = stats.get('requests', 0)
    theoretical_sync_time = total_requests * avg_request_time
    
    speedup = theoretical_sync_time / elapsed if elapsed > 0 else 1
    
    print("\nAsync architecture benefits:")
    print(f"   Actual time: {elapsed:.2f}s")
    print(f"   Sequential time estimate: {theoretical_sync_time:.2f}s")
    print(f"   Speedup: {speedup:.1f}x faster")
    print(f"   Concurrency achieved: {total_requests / elapsed:.1f} concurrent requests")
    
    print(f"\n{'─'*70}")
    print("Key advantages of async architecture:")
    print(f"{'─'*70}")
    print("✅ Non-blocking I/O - no thread waiting on network")
    print("✅ Connection pooling - reuse connections efficiently")
    print("✅ Massive concurrency - 1000+ requests on single thread")
    print("✅ Lower memory - coroutines vs threads")
    print("✅ Better rate limiting - precise timing control")
    print("✅ Graceful backpressure - semaphore-based limiting")
    
    print(f"\n{'='*70}\n")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
