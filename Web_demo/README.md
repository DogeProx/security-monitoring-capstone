# 🛡️ TÀI LIỆU BÀN GIAO MODULE: WEB DEMO & REPORTER

Tài liệu hướng dẫn sử dụng môi trường web thử nghiệm, bộ dữ liệu mẫu và mô-đun xuất báo cáo từ SQLite (hỗ trợ cả Windows và Linux).

---

## 1. Web Demo Server (`Web_demo/`)
Web demo cục bộ được dựng bằng thư viện chuẩn `http.server` của Python để kiểm thử các quy tắc HTTP Security Headers (`CSP`, `X-Content-Type-Options`) và Cookie Attributes (`HttpOnly`).

### Danh sách Endpoint kiểm thử
| Endpoint | Loại phản hồi | Mục đích kiểm thử |
|---|---|---|
| `/secure` | `text/html` | Trang cấu hình chuẩn (đủ CSP, XCTO, cookie có `HttpOnly`) — Kỳ vọng `0` phát hiện. |
| `/vuln-headers` | `text/html` | Trang thiếu header bảo mật (`CSP`, `X-Content-Type-Options`). |
| `/vuln-cookie` | `text/html` | Trang đặt cookie `session_id` thiếu cờ `HttpOnly`. |
| `/vuln-multi` | `text/html` | Trang chứa đồng thời nhiều lỗi (thiếu `CSP`, thiếu `XCTO`, cookie thiếu `HttpOnly`). |
| `/api/data` | `application/json` | API JSON dùng kiểm tra chống báo sai quy tắc HTML (`CSP`). |
| `/public-page` | `text/html` | Trang công khai không phát sinh `Set-Cookie`. |

* Bộ dữ liệu mục tiêu chuẩn được lưu tại: `Web_demo/demo_targets.json`.

### Khởi chạy Web Demo (Windows & Linux)
Chạy từ thư mục gốc của dự án và giữ cửa sổ terminal hoạt động:
```bash
python Web_demo/app.py