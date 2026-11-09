# BÀN GIAO CÔNG VIỆC -- DETECTION RULES MODULE

## 1. Thông tin dự án

**Tên dự án:** Automated Web Security Scanner with Dashboard + Alert System

**Repository:** https://github.com/DogeProx/security-monitoring-capstone

**Công nghệ:** Python 3.11+, Streamlit, SQLite, Git.

### Phân chia thành viên

| Thành viên | Phụ trách |
| :--- | :--- |
| Thành viên 1 | Dashboard -- Streamlit |
| Thành viên 2 | Web Scanner |
| Thành viên 3 | SQLite + Alert System |
| Thành viên 4 | Detection Rules |
| Thành viên 5 | Demo Web / Report / Integration Testing |

Người bàn giao phụ trách **Thành viên 4 — Detection Rules (Quy tắc phát hiện)**.

## 2. Trạng thái công việc

- Đã chốt danh sách 3 quy tắc cốt lõi: CSP (`SEC-HDR-CSP`), X-Content-Type-Options (`SEC-HDR-XCTO`), và HttpOnly cho cookie phiên (`SEC-CKI-HTTPONLY`).
- Đã đặc tả điều kiện áp dụng, phân loại mức độ nghiêm trọng (High, Medium, Low) và định nghĩa cách thu thập bằng chứng an toàn (tuyệt đối không lưu giá trị cookie/session token).
- Đã khởi tạo cấu trúc module `rules/` bằng Python thuần, tách biệt hoàn toàn logic kiểm tra khỏi tiến trình của HTTP client.
- Đã viết kịch bản kiểm thử tự động (`test_rules.py`) với dữ liệu phản hồi mô phỏng (mock data) bao phủ cả ca cấu hình chuẩn (Pass) và ca thiếu cấu hình (Fail).
- Đã commit, push mã nguồn lên nhánh riêng `feature/detection-rules` (hoặc tên nhánh bạn tự đặt) và tạo Pull Request chờ nhóm review.

## 3. Cấu trúc module quy tắc (`rules/`)

Các hàm xử lý quy tắc được phân chia thành các tệp chuyên biệt trong thư mục `rules/`:
- **`rules/__init__.py`**: Điểm vào (entry point) của module, xuất (export) hàm chính `analyze_response()` để các module khác dễ dàng import.
- **`rules/base.py`**: Chứa khung chuẩn (Base class) định nghĩa cấu trúc của một lỗi phát hiện (ID, mức độ, bằng chứng, cách khắc phục) để dễ mở rộng sau này.
- **`rules/headers.py`**: Chứa các hàm `check_csp()` và `check_xcto()` chuyên phân tích các HTTP headers bảo mật.
- **`rules/cookies.py`**: Chứa hàm `check_httponly()` chuyên quét danh sách cờ `Set-Cookie` của phản hồi.
- **`test_rules.py`**: File chạy unit test độc lập xác nhận các quy tắc hoạt động chính xác dựa trên mock data.

## 4. Hướng dẫn tích hợp dành cho các thành viên khác

### Dành cho Thành viên 2 (Web Scanner)
Module Scanner không cần phân tích lỗi, chỉ cần thu thập phản hồi, chuẩn hóa thành `dictionary` và gọi hàm `analyze_response` từ module này:
```python
from rules import analyze_response

# response_data là một từ điển chứa url, status_code, và headers (đã được chuẩn hóa từ Scanner)
response_data = {
    "url": "http://127.0.0.1/demo",
    "status_code": 200,
    "headers": {
        "Content-Type": "text/html",
        "Set-Cookie": "session_id=12345ABC; Path=/"
    }
}

# Gọi hàm phân tích và nhận lại danh sách các lỗi (findings)
findings = analyze_response(response_data)
```

### Dành cho Thành viên 3 (SQLite & Alert System)
Đầu ra của hàm `analyze_response` là một danh sách (list) các dictionary, đã được chuẩn hóa để Thành viên 3 lặp qua và đưa vào hàm `record_finding_and_alert(...)` của cơ sở dữ liệu:
```python
# Cấu trúc của mỗi finding trong danh sách trả về:
[
  {
    "rule_id": "SEC-CKI-HTTPONLY",
    "severity": "High",
    "evidence": "Cookie 'session_id' is missing HttpOnly flag.",
    "remediation": "Add HttpOnly flag to the session cookie creation logic."
  }
]
```

### Dành cho Thành viên 5 (Web Demo & Report)
- Yêu cầu Thành viên 5 thiết kế 2 trang web demo cục bộ để phục vụ tích hợp nghiệm thu: 
  1. Trang cấu hình chuẩn có đủ header `Content-Security-Policy`, `X-Content-Type-Options: nosniff` và cookie phiên có cờ `HttpOnly`.
  2. Trang lỗi bỏ trống toàn bộ các cấu hình bảo mật trên.

## 5. Lưu ý cho người tiếp quản

- Module `rules` chỉ có trách nhiệm phân tích tĩnh dữ liệu (static analysis) dựa trên `dictionary` đầu vào. **Tuyệt đối không thêm các thư viện gọi mạng (như `requests`, `urllib`) vào bên trong module này.**
- Mọi quy tắc thêm mới phải đảm bảo nguyên tắc "bằng chứng an toàn": Không in, không lưu các thông tin nhạy cảm của người dùng (Token, Session Value, v.v.).
- Chạy lệnh `python -m unittest test_rules.py` để kiểm tra độ toàn vẹn của logic trước khi tạo Pull Request mới.