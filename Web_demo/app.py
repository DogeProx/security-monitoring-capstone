import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = Path(__file__).resolve().parent
CSS_PATH = BASE_DIR / "static" / "style.css"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Web Demo ATTT</title>
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Web Demo An Toàn Thông Tin</h1>
            <p class="subtitle">Môi trường thử nghiệm bộ quét cấu hình bảo mật Web (Tuần 1 - Tuần 4)</p>
        </header>
        
        <nav>
            <a href="/" class="{active_home}">Trang chủ</a>
            <a href="/secure" class="{active_secure}">/secure</a>
            <a href="/vuln-headers" class="{active_vuln_headers}">/vuln-headers</a>
            <a href="/vuln-cookie" class="{active_vuln_cookie}">/vuln-cookie</a>
            <a href="/vuln-multi" class="{active_vuln_multi}">/vuln-multi</a>
            <a href="/public-page" class="{active_public_page}">/public-page</a>
            <a href="/api/data">/api/data</a>
        </nav>

        <main>
            {content}
        </main>

        <footer>
            <p>Đồ án Python Cho ATTT - Nhóm 5 Thành Viên</p>
        </footer>
    </div>
</body>
</html>
"""


class DemoHandler(BaseHTTPRequestHandler):
    def send_rendered_response(self, title, content, active_page, status=200, custom_headers=None, set_cookies=None):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')

        if custom_headers:
            for key, value in custom_headers.items():
                self.send_header(key, value)

        if set_cookies:
            for cookie in set_cookies:
                self.send_header('Set-Cookie', cookie)

        self.end_headers()

        active_dict = {
            'active_home': 'active' if active_page == 'home' else '',
            'active_secure': 'active' if active_page == 'secure' else '',
            'active_vuln_headers': 'active' if active_page == 'vuln_headers' else '',
            'active_vuln_cookie': 'active' if active_page == 'vuln_cookie' else '',
            'active_vuln_multi': 'active' if active_page == 'vuln_multi' else '',
            'active_public_page': 'active' if active_page == 'public_page' else '',
        }

        html = HTML_TEMPLATE.format(
            title=title,
            content=content,
            **active_dict
        )
        self.wfile.write(html.encode('utf-8'))

    def do_GET(self):
        if self.path == '/static/style.css':
            if CSS_PATH.exists():
                css_bytes = CSS_PATH.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'text/css; charset=utf-8')
                self.send_header('Content-Length', str(len(css_bytes)))
                self.end_headers()
                self.wfile.write(css_bytes)
            else:
                self.send_error(404, "Khong tim thay file style.css")

        elif self.path == '/secure':
            content = """
            <div class="card">
                <span class="badge badge-success">✓ Đạt chuẩn an toàn</span>
                <h2>Trang Cấu Hình Chuẩn</h2>
                <p>Trang này đã được cấu hình đầy đủ các Header bảo mật quan trọng và Cookie an toàn.</p>
                <div class="details">
                    + Content-Security-Policy: default-src 'self'<br>
                    + X-Content-Type-Options: nosniff<br>
                    + Set-Cookie: session_id=token123; HttpOnly; Path=/
                </div>
            </div>
            """
            self.send_rendered_response(
                title="Trang An Toàn",
                content=content,
                active_page="secure",
                custom_headers={
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Content-Type-Options': 'nosniff'
                },
                set_cookies=['session_id=token123; HttpOnly; Path=/']
            )

        elif self.path == '/vuln-headers':
            content = """
            <div class="card">
                <span class="badge badge-danger">⚠ Có lỗ hổng Header</span>
                <h2>Trang Thiếu Header Bảo Mật</h2>
                <p>Trang này cố tình <strong>KHÔNG</strong> trả về cờ CSP và X-Content-Type-Options trong phản hồi HTTP để Bộ Quét ghi nhận lỗi.</p>
                <div class="details">
                    - Content-Security-Policy: [THIẾU]<br>
                    - X-Content-Type-Options: [THIẾU]
                </div>
            </div>
            """
            self.send_rendered_response(
                title="Cố ý thiếu Header",
                content=content,
                active_page="vuln_headers"
            )

        elif self.path == '/vuln-cookie':
            content = """
            <div class="card">
                <span class="badge badge-warning">⚠ Có lỗ hổng Cookie</span>
                <h2>Trang Cookie Không An Toàn</h2>
                <p>Trang này khởi tạo Cookie phiên làm việc nhưng <strong>KHÔNG có thuộc tính HttpOnly</strong>, làm tăng nguy cơ bị tấn công XSS đánh cắp Session.</p>
                <div class="details">
                    - Set-Cookie: session_id=token456; Path=/ (Thiếu thuộc tính HttpOnly)
                </div>
            </div>
            """
            self.send_rendered_response(
                title="Cố ý thiếu HttpOnly",
                content=content,
                active_page="vuln_cookie",
                set_cookies=['session_id=token456; Path=/']
            )

        elif self.path == '/vuln-multi':
            content = """
            <div class="card">
                <span class="badge badge-danger">⚠ Nhiều lỗ hổng đồng thời (Tuần 4)</span>
                <h2>Trang Chứa Nhiều Lỗi Cấu Hình</h2>
                <p>Trang này kết hợp nhiều lỗi cùng lúc để kiểm thử khả năng ghi nhận đa phát hiện trong một lượt quét.</p>
                <div class="details">
                    - Content-Security-Policy: [THIẾU]<br>
                    - X-Content-Type-Options: [THIẾU]<br>
                    - Set-Cookie: session_id=xyz987654321; Path=/ (Thiếu HttpOnly)<br>
                    - Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k (Lộ thông tin phiên bản)
                </div>
            </div>
            """
            self.send_rendered_response(
                title="Nhiều Lỗ Hổng",
                content=content,
                active_page="vuln_multi",
                custom_headers={
                    'Server': 'Apache/2.4.49 (Unix) OpenSSL/1.1.1k'
                },
                set_cookies=['session_id=xyz987654321; Path=/']
            )

        elif self.path == '/public-page':
            content = """
            <div class="card">
                <span class="badge badge-info">ℹ Trang công khai sạch (Tuần 4)</span>
                <h2>Trang Không Đặt Cookie Phiên</h2>
                <p>Trang này cấu hình đầy đủ Security Headers nhưng không dùng Cookie, dùng để kiểm tra hệ thống không báo nhầm lỗi Cookie.</p>
                <div class="details">
                    + Content-Security-Policy: default-src 'self'<br>
                    + X-Content-Type-Options: nosniff<br>
                    + Set-Cookie: [KHÔNG CÓ]
                </div>
            </div>
            """
            self.send_rendered_response(
                title="Trang Công Khai",
                content=content,
                active_page="public_page",
                custom_headers={
                    'Content-Security-Policy': "default-src 'self'",
                    'X-Content-Type-Options': 'nosniff'
                }
            )

        elif self.path == '/api/data':
            payload = json.dumps({
                "status": "success",
                "message": "Du lieu API JSON phuc vu kiem thu chong bao sai",
                "data": [1, 2, 3]
            }, ensure_ascii=False).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        else:
            content = """
            <div class="card">
                <h2>Chào mừng đến với Web Demo</h2>
                <p>Đây là ứng dụng web thử nghiệm phục vụ cho bài tập đồ án. Nhấn vào các đường dẫn trên thanh menu để truy cập các trang tình huống kiểm thử bảo mật (Tuần 1 - Tuần 4).</p>
            </div>
            """
            self.send_rendered_response(
                title="Trang Chủ",
                content=content,
                active_page="home"
            )


if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 5000), DemoHandler)
    print("--------------------------------------------------")
    print("  🚀 Web Demo ATTT đã sẵn sàng (6 Endpoints)!")
    print("  🌐 Truy cập giao diện tại: http://127.0.0.1:5000")
    print("--------------------------------------------------")
try:
    server.serve_forever()
except KeyboardInterrupt:
    print("\n🛑 Đã dừng Web Demo.")
    server.server_close()