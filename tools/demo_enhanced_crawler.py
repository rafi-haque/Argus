#!/usr/bin/env python3
"""Enhanced Crawler Demo - Shows modern web crawling capabilities.

Demonstrates:
1. Playwright-based browser automation
2. JavaScript execution and rendering
3. XHR/Fetch request interception
4. WebSocket detection
5. SPA support
6. Form analysis
7. API endpoint extraction from JS
"""
import sys
import asyncio
from pathlib import Path

# Add argus to path
sys.path.insert(0, str(Path(__file__).parent))

from argus.modules.enhanced_crawler import EnhancedCrawler


async def demo_basic_crawl():
    """Demo basic crawling with JavaScript execution."""
    print("\n" + "="*70)
    print("  Test 1: Basic Crawl with JavaScript Execution")
    print("="*70)
    
    config = {
        'crawler': {
            'max_depth': 2,
            'headless': True,
            'wait_for_network': True,
            'auto_fill_forms': False
        },
        'performance': {
            'timeout': 10
        },
        'verbose': True
    }
    
    crawler = EnhancedCrawler(config)
    
    # Crawl a test site
    print("\n🕷️  Crawling example.com...")
    site_map = await crawler.crawl(
        'https://example.com',
        scope_config={'include_patterns': [r'example\.com']}
    )
    
    print(f"\n✅ Discovered {len(site_map)} endpoints:")
    for i, entry in enumerate(site_map[:5], 1):
        print(f"   {i}. [{entry['method']}] {entry['url']}")
        if entry.get('parameters'):
            for param in entry['parameters'][:3]:
                print(f"      - {param['name']} ({param['location']})")
    
    if len(site_map) > 5:
        print(f"   ... and {len(site_map) - 5} more")
    
    # Show WebSocket URLs
    websockets = crawler.get_websocket_urls()
    if websockets:
        print(f"\n🔌 WebSocket connections: {len(websockets)}")
        for ws_url in list(websockets)[:3]:
            print(f"   - {ws_url}")


async def demo_spa_crawl():
    """Demo SPA crawling with API interception."""
    print("\n" + "="*70)
    print("  Test 2: SPA Crawl with API Interception")
    print("="*70)
    
    config = {
        'crawler': {
            'max_depth': 1,
            'headless': True,
            'wait_for_network': True
        },
        'performance': {
            'timeout': 15
        },
        'verbose': True
    }
    
    crawler = EnhancedCrawler(config)
    
    # Crawl a SPA (use JSONPlaceholder as example)
    print("\n🕷️  Crawling JSONPlaceholder (API test site)...")
    site_map = await crawler.crawl(
        'https://jsonplaceholder.typicode.com',
        scope_config={'include_patterns': [r'jsonplaceholder']}
    )
    
    # Separate by source
    html_entries = [e for e in site_map if e.get('source') == 'html_crawl']
    api_entries = [e for e in site_map if e.get('source') == 'network_interception']
    js_entries = [e for e in site_map if e.get('source') == 'javascript_analysis']
    
    print(f"\n✅ Discovery Summary:")
    print(f"   HTML Crawl:      {len(html_entries)} endpoints")
    print(f"   API Interception: {len(api_entries)} endpoints")
    print(f"   JS Analysis:      {len(js_entries)} endpoints")
    print(f"   Total:           {len(site_map)} endpoints")
    
    if api_entries:
        print(f"\n📡 API Endpoints (XHR/Fetch):")
        for entry in api_entries[:5]:
            print(f"   [{entry['method']}] {entry['url']}")


async def demo_form_analysis():
    """Demo form analysis and parameter extraction."""
    print("\n" + "="*70)
    print("  Test 3: Form Analysis")
    print("="*70)
    
    config = {
        'crawler': {
            'max_depth': 1,
            'headless': True,
            'auto_fill_forms': True  # Enable auto-fill
        },
        'performance': {
            'timeout': 10
        },
        'verbose': True
    }
    
    crawler = EnhancedCrawler(config)
    
    # Crawl a site with forms (httpbin has form endpoints)
    print("\n🕷️  Crawling httpbin.org/forms...")
    site_map = await crawler.crawl(
        'https://httpbin.org/forms/post',
        scope_config={'include_patterns': [r'httpbin\.org']}
    )
    
    # Find form entries
    form_entries = [e for e in site_map if e.get('source') == 'form_analysis']
    
    print(f"\n✅ Found {len(form_entries)} forms:")
    for i, entry in enumerate(form_entries, 1):
        print(f"\n   Form {i}: [{entry['method']}] {entry['url']}")
        print(f"   Parameters ({len(entry['parameters'])}):")
        for param in entry['parameters'][:5]:
            param_type = param.get('type', 'text')
            print(f"      - {param['name']} (type: {param_type}, location: {param['location']})")


async def demo_js_analysis():
    """Demo JavaScript analysis for API endpoints."""
    print("\n" + "="*70)
    print("  Test 4: JavaScript Analysis")
    print("="*70)
    
    from argus.modules.enhanced_crawler import JavaScriptAnalyzer
    
    # Sample JavaScript code
    sample_js = """
    const API_BASE = '/api/v1';
    
    async function fetchUsers() {
        const response = await fetch(`${API_BASE}/users?page=1&limit=10`);
        return response.json();
    }
    
    function createUser(data) {
        return axios.post('/api/v1/users', {
            username: data.username,
            email: data.email,
            password: data.password
        });
    }
    
    $.ajax({
        url: '/rest/products',
        method: 'GET',
        data: { category: 'electronics', sort: 'price' }
    });
    
    const config = {
        endpoint: '/graphql',
        websocket: 'wss://api.example.com/ws',
        params: {
            query: '',
            variables: {}
        }
    };
    """
    
    analyzer = JavaScriptAnalyzer()
    findings = analyzer.analyze_script(sample_js, 'https://example.com')
    
    print(f"\n✅ Extracted {len(findings)} endpoints from JavaScript:")
    for finding in findings:
        print(f"   {finding['url']}")
        if finding['parameters']:
            print(f"      Parameters: {', '.join(p['name'] for p in finding['parameters'])}")


async def main():
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║          Enhanced Crawler - Interactive Demo                     ║
║                                                                   ║
║  Demonstrates modern web crawling with Playwright                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    print("\n🚀 Starting Enhanced Crawler Demonstrations...\n")
    
    try:
        # Test 1: Basic crawl
        await demo_basic_crawl()
        
        # Test 2: SPA crawl
        await demo_spa_crawl()
        
        # Test 3: Form analysis
        await demo_form_analysis()
        
        # Test 4: JS analysis
        await demo_js_analysis()
        
        print("\n" + "="*70)
        print("  Summary")
        print("="*70)
        print("""
   ✅ All demonstrations completed successfully!
   
   Key Features Demonstrated:
   • Browser automation with Playwright
   • JavaScript execution and rendering
   • XHR/Fetch request interception
   • WebSocket connection detection
   • Form analysis with auto-fill
   • API endpoint extraction from JS code
   • SPA support with network monitoring
   
   Advantages over Basic Crawler:
   • Discovers AJAX endpoints (invisible to basic crawlers)
   • Handles JavaScript-rendered content
   • Detects WebSocket connections
   • Extracts API endpoints from JS bundles
   • Auto-fills forms to discover POST parameters
   • Supports modern SPAs (React, Vue, Angular)
   
   Usage:
   from argus.modules.enhanced_crawler import EnhancedCrawler
   
   config = {
       'crawler': {
           'max_depth': 3,
           'headless': True,
           'wait_for_network': True,
           'auto_fill_forms': True
       },
       'performance': {'timeout': 10},
       'verbose': True
   }
   
   crawler = EnhancedCrawler(config)
   site_map = await crawler.crawl(url, scope_config)
        """)
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    asyncio.run(main())
