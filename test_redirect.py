from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest

from scanner import scan_url


class RedirectTests(unittest.TestCase):
    def test_blocks_redirect_after_receiving_response(self):
        destination_requests = []
        source_requests = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                destination_requests.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler) as destination:
            destination_url = f"http://127.0.0.1:{destination.server_port}/outside"

            class RedirectHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    source_requests.append(self.path)
                    self.send_response(302)
                    self.send_header("Location", destination_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, *args):
                    pass

            with ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler) as source:
                servers = (source, destination)
                threads = [
                    Thread(target=server.serve_forever, daemon=True) for server in servers
                ]
                for thread in threads:
                    thread.start()
                origin = f"http://127.0.0.1:{source.server_port}"
                try:
                    result = scan_url(origin + "/", [origin])
                finally:
                    for server in servers:
                        server.shutdown()
                    for thread in threads:
                        thread.join()

        self.assertEqual(source_requests, ["/"])
        self.assertEqual(destination_requests, [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "Redirect target is outside allowed scope")
        self.assertEqual(result["final_url"], destination_url)
        self.assertEqual(result["redirect_count"], 0)
        self.assertIsNone(result["status_code"])
        print("PASS redirect: received local HTTP 302; destination requests = 0; blocked outside origin.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
