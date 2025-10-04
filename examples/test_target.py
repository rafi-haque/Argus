#!/usr/bin/env python3
"""
Simple vulnerable web app for testing Argus scanner.
DO NOT USE IN PRODUCTION - Contains intentional vulnerabilities!
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

class VulnerableHandler(BaseHTTPRequestHandler):
    """HTTP handler with intentional vulnerabilities for testing."""
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        if path == '/':
            self.send_home_page()
        elif path == '/search':
            self.send_search_page(query.get('q', [''])[0])
        elif path.startswith('/user/'):
            user_id = path.split('/')[-1]
            self.send_user_page(user_id)
        elif path == '/admin':
            self.send_admin_page()
        elif path == '/api/data':
            self.send_api_response()
        elif path == '/download':
            self.send_download_page(query.get('file', [''])[0])
        else:
            self.send_404()
    
    def do_POST(self):
        """Handle POST requests."""
        if self.path == '/admin':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            self.send_admin_action(body)
        else:
            self.send_404()
    
    def send_home_page(self):
        """Send home page."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Target App</title>
        </head>
        <body>
            <h1>Test Target Application</h1>
            <p>This is a test application with intentional vulnerabilities for scanner testing.</p>
            
            <h2>Available Endpoints:</h2>
            <ul>
                <li><a href="/search?q=test">/search?q=test</a> - Search function</li>
                <li><a href="/user/1">/user/1</a> - User profile</li>
                <li><a href="/admin">/admin</a> - Admin panel</li>
                <li><a href="/api/data">/api/data</a> - API endpoint</li>
                <li><a href="/download?file=doc.txt">/download?file=doc.txt</a> - File download</li>
            </ul>
        </body>
        </html>
        """
        self.send_html(html)
    
    def send_search_page(self, query):
        """Send search results (XSS vulnerable)."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Search Results</title></head>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {query}</p>
            <p>No results found.</p>
            <a href="/">Back to Home</a>
        </body>
        </html>
        """
        self.send_html(html)
    
    def send_user_page(self, user_id):
        """Send user profile (SQLi vulnerable)."""
        if "'" in user_id or "OR" in user_id.upper():
            html = f"""
            <html>
            <body>
                <h1>Database Error</h1>
                <p style="color: red;">SQL syntax error near 'SELECT * FROM users WHERE id='{user_id}'</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
        else:
            html = f"""
            <html>
            <body>
                <h1>User Profile #{user_id}</h1>
                <p>Username: user{user_id}</p>
                <p>Email: user{user_id}@example.com</p>
                <a href="/">Back to Home</a>
            </body>
            </html>
            """
        self.send_html(html)
    
    def send_admin_page(self):
        """Send admin panel (CSRF vulnerable - no token)."""
        html = """
        <html>
        <body>
            <h1>Admin Panel</h1>
            <form method="POST" action="/admin">
                <input type="text" name="action" placeholder="Enter action">
                <button type="submit">Execute</button>
            </form>
            <a href="/">Back to Home</a>
        </body>
        </html>
        """
        self.send_html(html)
    
    def send_admin_action(self, body):
        """Handle admin action."""
        html = f"<html><body><h1>Action Executed</h1><p>{body}</p><a href='/'>Back</a></body></html>"
        self.send_html(html)
    
    def send_api_response(self):
        """Send API response (missing security headers)."""
        data = {
            'status': 'success',
            'data': [
                {'id': 1, 'name': 'Item 1'},
                {'id': 2, 'name': 'Item 2'}
            ]
        }
        self.send_json(data)
    
    def send_download_page(self, filename):
        """Send download page (path traversal vulnerable)."""
        if '../' in filename or '..' in filename:
            html = "<html><body><h1>Error</h1><p style='color:red'>Invalid file path detected</p></body></html>"
        else:
            html = f"<html><body><h1>File Download</h1><p>Downloading: {filename}</p></body></html>"
        self.send_html(html)
    
    def send_html(self, html):
        """Send HTML response."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(html.encode('utf-8')))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def send_json(self, data):
        """Send JSON response."""
        json_data = json.dumps(data)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(json_data.encode('utf-8')))
        self.end_headers()
        self.wfile.write(json_data.encode('utf-8'))
    
    def send_404(self):
        """Send 404 response."""
        html = "<html><body><h1>404 Not Found</h1></body></html>"
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(html.encode('utf-8')))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

if __name__ == '__main__':
    print("=" * 60)
    print("⚠️  TEST TARGET SERVER - VULNERABLE BY DESIGN")
    print("=" * 60)
    print("Starting server on http://127.0.0.1:8888")
    print("This server contains INTENTIONAL vulnerabilities for testing.")
    print("DO NOT expose to the internet!")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    server = HTTPServer(('127.0.0.1', 8888), VulnerableHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nServer stopped.")
        server.shutdown()
