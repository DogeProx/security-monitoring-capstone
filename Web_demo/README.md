# 🛡️ TÀI LIỆU BÀN GIAO MODULE: WEB DEMO & REPORTER

Tài liệu hướng dẫn sử dụng môi trường web thử nghiệm, bộ dữ liệu mẫu và mô-đun xuất báo cáo từ SQLite (hỗ trợ cả Windows và Linux).

---

## 1. Web Demo Server (`Web_demo/`)

Web demo cục bộ được dựng bằng thư viện chuẩn `http.server` của Python để kiểm thử các quy tắc HTTP Security Headers (`CSP`, `X-Content-Type-Options`) và Cookie Attributes (`HttpOnly`).

### Danh sách 7 Endpoint kiểm thử

| Endpoint | Mã HTTP | Loại phản hồi | Mục đích kiểm thử |
|---|---|---|---|
| `/secure` | `200` | `text/html` | Trang cấu hình chuẩn (đủ CSP, XCTO, cookie có `HttpOnly`) — Kỳ vọng `0` phát hiện. |
| `/vuln-headers` | `200` | `text/html` | Trang thiếu header bảo mật (`CSP`, `X-Content-Type-Options`). |
| `/vuln-cookie` | `200` | `text/html` | Trang đặt cookie `session_id` thiếu cờ `HttpOnly`. |
| `/vuln-multi` | `200` | `text/html` | Trang chứa đồng thời nhiều lỗi (thiếu `CSP`, thiếu `XCTO`, cookie thiếu `HttpOnly`). |
| `/api/data` | `200` | `application/json` | API JSON dùng kiểm tra chống báo sai quy tắc HTML (`CSP`). |
| `/public-page` | `200` | `text/html` | Trang công khai cấu hình đủ header bảo mật và không phát sinh `Set-Cookie`. |
| `/error` | `500` | `text/html` | Trang giả lập lỗi máy chủ HTTP 500 để kiểm thử khả năng xử lý trang lỗi của bộ quét. |

* **Cấu hình mục tiêu dùng chung (`Web_demo/config.py`):** Gồm 3 trang demo mặc định (`/secure`, `/vuln-headers`, `/vuln-cookie`) phục vụ Dashboard, CLI và kịch bản trình bày Tuần 6.
* **Bộ dữ liệu kiểm thử đầy đủ (`Web_demo/demo_targets.json`):** Danh sách toàn bộ 7 endpoint phục vụ kiểm thử mở rộng và ca biên.

### Khởi chạy Web Demo (Windows & Linux)

Chạy từ thư mục gốc của dự án và giữ cửa sổ terminal hoạt động tại `http://127.0.0.1:5000`:

```bash
python -X utf8 Web_demo/app.py