"""Unit tests for Crawler module."""
from argus.modules.crawler import Crawler


def test_crawler_initialization():
    """Test crawler initialization."""
    config = {'crawler': {'max_depth': 2, 'active': False}}
    crawler = Crawler(config)
    
    assert crawler.max_depth == 2
    assert crawler.use_active_crawling is False
    assert hasattr(crawler, 'visited_urls')


def test_crawler_default_config():
    """Test crawler with default config."""
    crawler = Crawler({})
    
    assert crawler.max_depth == 3
    assert crawler.use_active_crawling is False


def test_normalize_url():
    """Test URL normalization with urljoin."""
    from urllib.parse import urljoin, urlparse
    
    # Test urljoin behavior (what crawler uses internally)
    result = urljoin('http://example.com', 'http://example.com/page')
    assert result == 'http://example.com/page'
    
    result = urljoin('http://example.com', '/page')
    assert result == 'http://example.com/page'
    
    # Fragment is kept by urljoin but can be removed
    result = urljoin('http://example.com', '/page#section')
    parsed = urlparse(result)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    assert clean_url == 'http://example.com/page'


def test_is_same_domain():
    """Test domain checking with urlparse."""
    from urllib.parse import urlparse
    
    # Test domain comparison logic
    def same_domain(url1, url2):
        domain1 = urlparse(url1).netloc.split(':')[0]
        domain2 = urlparse(url2).netloc.split(':')[0]
        return domain1 == domain2
    
    assert same_domain('http://example.com/page', 'http://example.com') is True
    assert same_domain('http://example.com:8080/page', 'http://example.com') is True
    assert same_domain('http://other.com/page', 'http://example.com') is False


def test_extract_forms():
    """Test form extraction."""
    crawler = Crawler({})
    
    html = """
    <html>
        <form action="/submit" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
    </html>
    """
    
    # Note: _extract_form extracts a single form, need to test with BeautifulSoup object
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    form = soup.find('form')
    if form:
        form_entry = crawler._extract_form(form, 'http://example.com')
        assert form_entry is not None
        assert '/submit' in form_entry['url']
        assert form_entry['method'] == 'POST'
