from http.server import HTTPServer, BaseHTTPRequestHandler

# Khung HTML & CSS dùng chung cho giao diện đẹp
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Web Demo ATTT</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; line-height: 1.6; padding: 20px; }}
        .container {{ max-width: 800px; margin: 30px auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        header {{ text-align: center; border-bottom: 2px solid #eef2f5; padding-bottom: 20px; margin-bottom: 25px; }}
        h1 {{ color: #1e293b; font-size: 26px; margin-bottom: 8px; }}
        p.subtitle {{ color: #64748b; font-size: 15px; }}
        nav {{ display: flex; gap: 10px; justify-content: center; margin-bottom: 25px; wrap: flex-wrap; }}
        nav a {{ text-decoration: none; padding: 8px 16px; border-radius: 6px; background: #f1f5f9; color: #475569; font-weight: 600; font-size: 14px; transition: all 0.2s; }}
        nav a:hover {{ background: #e2e8f0; color: #0f172a; }}
        nav a.active {{ background: #2563eb; color: #fff; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 12px; }}
        .badge-success {{ background: #dcfce7; color: #15803d; }}
        .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
        .badge-warning {{ background: #fef3c7; color: #b45309; }}
        .details {{ background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; font-family: 'Courier New', Courier, monospace; font-size: 13px; overflow-x: auto; margin-top: 15px; }}
        footer {{ text-align: center; margin-top: 30px; font-size: 13px; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Web Demo An Toàn Thông Tin</h1>
            <p class="subtitle">Môi trường thử nghiệm bộ quét cấu hình bảo mật Web (GET Requests)</p>
        </header>
        
        <nav>
            <a href="/" class="{active_home}">Trang chủ</a>
            <a href="/secure" class="{active_secure}">/secure</a>
            <a href="/vuln-headers" class="{active_vuln_headers}">/vuln-headers</a>
            <a href="/vuln-cookie" class="{active_vuln_cookie}">/vuln-cookie</a>
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
        
        # Thêm header tùy chỉnh nếu có
        if custom_headers:
            for key, value in custom_headers.items():
                self.send_header(key, value)
                
        # Thêm cookie tùy chỉnh nếu có
        if set_cookies:
            for cookie in set_cookies:
                self.send_header('Set-Cookie', cookie)
                
        self.end_headers()

        # Đánh dấu tab đang active
        active_dict = {
            'active_home': 'active' if active_page == 'home' else '',
            'active_secure': 'active' if active_page == 'secure' else '',
            'active_vuln_headers': 'active' if active_page == 'vuln_headers' else '',
            'active_vuln_cookie': 'active' if active_page == 'vuln_cookie' else ''
        }

        html = HTML_TEMPLATE.format(
            title=title,
            content=content,
            **active_dict
        )
        self.wfile.write(html.encode('utf-8'))

    def do_GET(self):
        if self.path == '/secure':
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

        else: # Trang chủ '/'
            content = """
            <div class="card">
                <h2>Chào mừng đến với Web Demo</h2>
                <p>Đây là ứng dụng web thử nghiệm phục vụ cho bài tập đồ án. Nhấn vào các đường dẫn trên thanh menu để truy cập các trang tình huống kiểm thử bảo mật.</p>
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
    print("  🚀 Web Demo ATTT đã sẵn sàng!")
    print("  🌐 Truy cập giao diện tại: http://127.0.0.1:5000")
    print("--------------------------------------------------")
    server.serve_forever()