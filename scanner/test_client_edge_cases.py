
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner.client import scan_url


class TestHandler(BaseHTTPRequestHandler):
    __test__ = False

    def do_GET(self):
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Set-Cookie",
                "sessionid=abc123; HttpOnly; Secure; SameSite=Lax"
            )
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

        elif self.path == "/redirect-internal":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "https://google.com")
            self.send_header("Content-Length", "0")
            self.end_headers()

        elif self.path == "/slow":
            time.sleep(1.5)
            try:
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")
            except (BrokenPipeError, ConnectionResetError):
                pass

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, format, *args):
        pass


class ScannerEdgeCaseTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            TestHandler
        )

        cls.port = cls.server.server_address[1]

        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True
        )
        cls.thread.start()

        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.allowed_hosts = ["127.0.0.1"]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_normal_response_and_headers(self):
        result = scan_url(
            self.base_url + "/ok",
            self.allowed_hosts
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["status_code"], 200)
        self.assertIn("Content-Security-Policy", result["headers"])
        self.assertIn("X-Content-Type-Options", result["headers"])

    def test_cookie_attributes(self):
        result = scan_url(
            self.base_url + "/ok",
            self.allowed_hosts
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["cookies"]), 1)

        cookie = result["cookies"][0]

        self.assertTrue(cookie["httponly"])
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["samesite"], "Lax")

    def test_internal_redirect(self):
        result = scan_url(
            self.base_url + "/redirect-internal",
            self.allowed_hosts
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["redirect_count"], 1)

    def test_external_redirect_blocked(self):
        result = scan_url(
            self.base_url + "/redirect-external",
            self.allowed_hosts
        )

        self.assertEqual(result["status"], "failed")
        self.assertIn("outside allowed scope", result["error"])

    def test_timeout(self):
        result = scan_url(
            self.base_url + "/slow",
            self.allowed_hosts,
            timeout=0.2
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "Request timeout")


if __name__ == "__main__":
    unittest.main(verbosity=2)
