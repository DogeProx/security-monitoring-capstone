from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from scanner import scan_url


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "https://google.com")
        self.end_headers()

    def log_message(self, format, *args):
        pass


server = HTTPServer(("127.0.0.1", 8000), RedirectHandler)

thread = Thread(target=server.serve_forever, daemon=True)
thread.start()

try:
    result = scan_url(
        url="http://127.0.0.1:8000",
        allowed_hosts=["127.0.0.1"],
        timeout=5
    )

    print(result)

finally:
    server.shutdown()
    server.server_close()