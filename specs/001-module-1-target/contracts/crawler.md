# Contract: Crawler Interface

## Overview
The crawler discovers the attack surface by finding URLs and parameters. Supports both passive and active crawling modes.

## Interface Definition

### Class: BaseCrawler
```python
class BaseCrawler:
    def __init__(self, config: dict):
        """Initialize with scanner config"""
        pass

    def crawl(self, seed_url: str, scope_config: dict) -> list:
        """Discover site endpoints and parameters
        
        Args:
            seed_url: Starting URL for crawling
            scope_config: Include/exclude patterns
        
        Returns:
            list: Site map entries
        """
        pass
```

## Site Map Entry Structure
Each entry dict must contain:
```python
{
    'url': str,        # Full URL
    'method': str,     # HTTP method (default 'GET')
    'parameters': [    # List of parameter dicts
        {
            'name': str,
            'value': str,     # Sample/current value
            'location': str   # 'query', 'body', 'header', 'cookie'
        }
    ]
}
```

## Crawling Modes

### Passive Crawling
- Parse HTML responses for <a href>, <form action>, etc.
- Extract links using BeautifulSoup
- Follow same-domain links recursively
- Depth limit to prevent infinite crawling

### Active Crawling
- Use headless browser (Playwright) to render JS
- Discover AJAX requests and dynamic content
- Extract links from DOM and network logs
- Handle SPAs and JS-heavy applications

## Implementation Requirements
- Respect robots.txt (optional but recommended)
- Stay within configured scope (include/exclude regex)
- Handle redirects and relative URLs
- Deduplicate URLs
- Extract parameters from URLs, forms, and JS
- Timeout handling for slow pages
- Memory efficient for large sites

## Examples

### Passive Crawler
- GET seed URL
- Parse HTML for links
- Recursively crawl discovered URLs
- Extract query parameters from URLs

### Active Crawler
- Launch headless browser
- Navigate to seed URL
- Monitor network requests
- Extract links from rendered DOM
- Close browser after crawling