# Web Scanner Module

## 1. Giới thiệu

Web Scanner là module chịu trách nhiệm gửi HTTP request đến các website nằm trong phạm vi được cho phép, thu thập thông tin phản hồi và chuẩn hóa kết quả để chuyển sang Detection Rules phân tích.

Module được phát triển bằng Python, sử dụng thư viện `requests`.

Các chức năng chính:

- Gửi HTTP GET request đến mục tiêu.
- Kiểm tra phạm vi URL được phép quét (Scope Validation).
- Theo dõi và kiểm soát HTTP Redirect.
- Giới hạn thời gian chờ (Timeout).
- Thu thập HTTP Status Code, Headers và Cookie Attributes.
- Chuẩn hóa kết quả quét.
- Hỗ trợ quét nhiều URL và theo dõi tiến độ.

## 2. Kiến trúc module

```text
scanner/
│
├── client.py
├── runner.py
├── scope.py
├── README.MD
│
├── test_client.py
├── test_client_edge_cases.py
├── test_public_interface.py
├── test_result_schema.py
├── test_runner.py
├── test_scope.py
└── test_scope_integration.py
```

### Vai trò từng file

| File | Chức năng |
|---|---|
| client.py | Thực hiện HTTP request và thu thập response |
| runner.py | Điều phối quá trình quét nhiều URL |
| scope.py | Kiểm tra URL có thuộc phạm vi cho phép |
| test_client.py | Kiểm thử HTTP Client |
| test_client_edge_cases.py | Kiểm thử các tình huống biên |
| test_public_interface.py | Kiểm tra giao diện sử dụng công khai |
| test_result_schema.py | Kiểm tra cấu trúc kết quả |
| test_runner.py | Kiểm thử quá trình điều phối |

## 3. Luồng hoạt động

```text
Danh sách URL
      |
      v
     Runner
      |
      v
  HTTP Client
      |
      v
 Scope Validation
      |
      v
 HTTP GET Request
      |
      v
 Kiểm tra Redirect
      |
      v
 Thu thập Response
      |
      v
 Chuẩn hóa kết quả
      |
      v
 Detection Rules
```

## 4. Các chức năng chính

### 4.1. Scope Validation

Chỉ cho phép scanner truy cập các hostname nằm trong danh sách `allowed_hosts`.

Nếu URL nằm ngoài phạm vi cho phép, scanner từ chối request.

### 4.2. HTTP Request

Scanner sử dụng HTTP GET để gửi request đến website mục tiêu.

Thông tin thu thập:

- HTTP Status Code.
- Response Headers.
- Cookie Attributes.
- Số lần Redirect.
- Thời gian quét.
- Trạng thái request.

### 4.3. Redirect Validation

Scanner hỗ trợ các mã chuyển hướng:

- 301
- 302
- 303
- 307
- 308

Mỗi redirect được kiểm tra phạm vi trước khi tiếp tục truy cập.

Nếu redirect dẫn đến hostname ngoài phạm vi, scanner dừng quá trình truy cập.

### 4.4. Timeout Handling

Scanner giới hạn thời gian chờ phản hồi từ server.

Nếu request vượt quá thời gian cho phép, kết quả được đánh dấu thất bại thay vì làm dừng toàn bộ quá trình quét.

### 4.5. Multi-URL Scanning

Runner chịu trách nhiệm điều phối nhiều URL.

Các trạng thái tổng hợp:

| Trạng thái | Ý nghĩa |
|---|---|
| completed | Tất cả URL quét thành công |
| partial | Có URL thành công và URL thất bại |
| failed | Không có URL nào quét thành công |

Runner cũng hỗ trợ `progress_callback` để cập nhật tiến độ cho Worker.

## 5. Giao diện sử dụng

Module cung cấp hàm `run_scan()` để các thành phần khác sử dụng.

Ví dụ:

```python
from scanner import run_scan

report = run_scan(
    targets=[
        "https://example.com"
    ],
    allowed_hosts=[
        "example.com"
    ]
)

print(report)
```

Các tham số chính:

| Tham số | Ý nghĩa |
|---|---|
| targets | Danh sách URL cần quét |
| allowed_hosts | Danh sách hostname được phép |
| timeout | Thời gian chờ request |
| max_redirects | Số redirect tối đa |
| progress_callback | Hàm cập nhật tiến độ |
| scan_id | Mã lượt quét được cung cấp từ bên ngoài nếu cần |

## 6. Kiểm thử

Chạy toàn bộ test của module:

```powershell
python -m pytest scanner -v
```

Các nhóm kiểm thử:

- HTTP Response và Headers.
- Cookie Attributes.
- Internal Redirect.
- External Redirect Blocking.
- Timeout Handling.
- Public Interface.
- Result Schema.
- Multi-URL Scanning.
- Partial Scan.
- Progress Callback.

Kết quả kiểm thử hiện tại:

**11 passed, 0 failed.**

## 7. Tích hợp với hệ thống

Web Scanner được tích hợp với các module khác theo luồng:

1. Worker nhận Scan Job từ SQLite.
2. Worker gọi Runner.
3. Runner điều phối các URL.
4. Client thực hiện HTTP request.
5. Kết quả được chuyển sang Detection Rules.
6. Findings được lưu vào SQLite.
7. Alert được tạo nếu Finding đạt ngưỡng Severity.
8. Dashboard đọc và hiển thị dữ liệu.

## 8. Giới hạn hiện tại

Phiên bản hiện tại tập trung vào thu thập thông tin HTTP và hỗ trợ các Detection Rules cơ bản.

Chưa triển khai:

- SQL Injection Detection.
- Cross-Site Scripting Detection.
- Path Traversal Detection.
- File Upload Vulnerability Detection.
- JavaScript Rendering.
- Full Website Crawling.

Đây là các chức năng có thể mở rộng trong những phiên bản tiếp theo.

## 9. Hướng phát triển

- Bổ sung khả năng crawl nhiều trang.
- Cải thiện quản lý HTTP Session.
- Bổ sung kiểm thử cho các tình huống mạng phức tạp.
- Hỗ trợ cấu hình User-Agent.
- Cải thiện khả năng thu thập nhiều Set-Cookie headers.
- Tối ưu hiệu suất khi quét nhiều URL.
