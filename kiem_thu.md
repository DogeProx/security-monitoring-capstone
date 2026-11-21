# WEEK 6 – KIỂM THỬ VÀ DEMO HỆ THỐNG AUTOMATED WEB SECURITY SCANNER

## 1. Mục tiêu tuần 6

Tuần 6 tập trung kiểm tra luồng hoạt động của hệ thống Automated Web Security Scanner, bao gồm:

- Khởi chạy Web Demo và thực hiện quét các URL mục tiêu.
- Kiểm tra luồng xử lý scan job thông qua Worker và Queue.
- Theo dõi kết quả quét trên Dashboard.
- Kiểm tra các tình huống HTTP 500, FAILED và PARTIAL.
- Kiểm tra cơ chế xử lý HTTP redirect và ngăn Scanner truy cập URL nằm ngoài phạm vi cho phép.

## 2. Môi trường kiểm thử

- Hệ điều hành: Windows.
- Terminal: PowerShell.
- Python environment: `.venv`.
- Web Demo: thư viện chuẩn Python http.server, chạy tại `http://127.0.0.1:5000`.
- Dashboard: Streamlit, chạy tại `http://127.0.0.1:8501`.
- Cơ sở dữ liệu: SQLite (`security_monitoring.db`).

### 2.1. Khởi chạy Web Demo

Tại thư mục gốc dự án, chạy:

```powershell
python -X utf8 Web_demo/app.py
```

Web Demo cung cấp các endpoint phục vụ kiểm thử, bao gồm:

- `/secure`
- `/vuln-headers`
- `/vuln-cookie`
- `/vuln-multi`
- `/public-page`
- `/api/data`
- `/error`

### 2.2. Khởi chạy Worker

Mở một Terminal riêng tại thư mục gốc dự án:

```powershell
python worker.py
```

Worker nhận các scan job từ Queue và thực hiện xử lý.

### 2.3. Khởi chạy Dashboard

Mở một Terminal khác:

```powershell
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Truy cập Dashboard tại:

`http://127.0.0.1:8501`

Giữ các Terminal tương ứng hoạt động trong quá trình kiểm thử.

## 3. Kiểm thử quét trực tiếp và Dashboard

### 3.1. Chạy Scanner trực tiếp

Chạy lệnh:

```powershell
python integration.py
```

Kết quả kiểm thử đã ghi nhận:

- Scan ID: `6896a22a-ee01-46a3-b339-a7138e62d93b`
- Số URL hoàn tất: `3/3`
- Các URL được kiểm thử:
  - `/secure`
  - `/vuln-headers`
  - `/vuln-cookie`

### 3.2. Tạo scan job qua Queue

Chạy:

```powershell
python integration.py --enqueue
```

Một Scan ID đã được ghi nhận trong quá trình kiểm thử:

`73e3c28e-33f9-4c02-8bec-c6e24a5e154d`

Worker xử lý các job được đưa vào Queue. Trong log khởi động Worker có ghi nhận:

`Recovered jobs: 1`

### 3.3. Số liệu Dashboard tại thời điểm chụp

Dashboard từng ghi nhận các số liệu sau:

| Chỉ số | Giá trị |
|---|---:|
| Tổng lượt quét | 113 |
| Tổng URL mục tiêu | 319 |
| Tổng findings | 403 |
| Tổng alerts | 79 |

Đây là số liệu tại thời điểm chụp ảnh kiểm thử, không phải số liệu cố định của hệ thống.

### 3.4. Một số findings được quan sát

| URL | Rule | Mức độ |
|---|---|---|
| `/vuln-cookie` | `SEC-CKI-HTTPONLY` | High |
| `/vuln-cookie` | `SEC-HDR-XCTO` | Low |
| `/vuln-cookie` | `SEC-HDR-CSP` | Medium |
| `/vuln-headers` | `SEC-HDR-XCTO` | Low |
| `/vuln-headers` | `SEC-HDR-CSP` | Medium |

Các findings trên là kết quả quan sát được trong lượt demo tương ứng.

## 4. Kiểm thử trường hợp HTTP 500

### 4.1. Mục tiêu

Kiểm tra cách Scanner xử lý khi máy chủ đích trả về mã trạng thái HTTP `500 Internal Server Error`.

### 4.2. URL kiểm thử

`http://127.0.0.1:5000/error`

Endpoint `/error` của Web Demo được thiết kế để trả về trang lỗi HTTP 500.

### 4.3. Cách thực hiện

Đảm bảo Web Demo đang chạy, sau đó tạo scan job:

```powershell
python integration.py --url http://127.0.0.1:5000/error --enqueue
```

Worker xử lý job và kết quả được theo dõi trên Dashboard.

### 4.4. Kết quả thực tế

- Scan ID: `03f8078f-17c6-4da0-92ea-4f5bf5ddfdc9`
- URL mục tiêu: `http://127.0.0.1:5000/error`
- HTTP Status Code: `500 Internal Server Error`
- Trạng thái lượt quét trên Dashboard: `Hoàn tất`
- URL thành công: `1`
- Tổng URL: `1`
- Thông tin lỗi trên Dashboard: `—`

### 4.5. Nhận xét

Máy chủ vẫn thiết lập kết nối và trả về phản hồi HTTP 500. Theo logic xử lý hiện tại của hệ thống, Scanner nhận được phản hồi HTTP nên URL được ghi nhận là `completed`; do đó lượt quét có trạng thái `Hoàn tất`.

Điều này khác với trường hợp FAILED, trong đó Scanner không thể kết nối đến máy chủ và không nhận được phản hồi HTTP.

### 4.6. Bằng chứng

Kết quả kiểm thử tự động cho ca HTTP 500 được lưu trong [log nghiệm thu](docs/week6_scanner_results.txt).

## 5. Kiểm thử trường hợp FAILED

### 5.1. Mục tiêu

Kiểm tra cách hệ thống xử lý khi URL mục tiêu không thể kết nối được và Scanner không nhận được phản hồi HTTP.

### 5.2. URL kiểm thử

`http://127.0.0.1:59999`

Cổng `59999` không có dịch vụ lắng nghe tại thời điểm kiểm thử, do đó kết nối bị từ chối.

### 5.3. Cách thực hiện

Tạo scan job:

```powershell
python integration.py --url http://127.0.0.1:59999 --enqueue
```

Sau đó để Worker xử lý job và kiểm tra trạng thái trên Dashboard.

### 5.4. Kết quả thực tế

- Scan ID: `7deedaf1-e618-4ab2-b3bb-0d63288d2344`
- URL mục tiêu: `http://127.0.0.1:59999`
- Trạng thái: `Thất bại (FAILED)`
- Tổng URL: `1`
- URL thành công: `0`
- Thông tin lỗi: `ConnectionError` / connection refused.

### 5.5. Nhận xét

Scanner không thể thiết lập kết nối tới máy chủ tại `127.0.0.1:59999`, vì vậy không nhận được phản hồi HTTP. Hệ thống ghi nhận URL thất bại và lượt quét có trạng thái FAILED.

### 5.6. Bằng chứng

Kết quả kiểm thử tự động cho ca FAILED được lưu trong [log nghiệm thu](docs/week6_scanner_results.txt).

## 6. Kiểm thử trường hợp PARTIAL

### 6.1. Mục tiêu

Kiểm tra khả năng xử lý một lượt quét có nhiều URL, trong đó có URL truy cập được và URL không thể kết nối.

### 6.2. Các URL kiểm thử

1. `http://127.0.0.1:5000/secure` – URL truy cập thành công.
2. `http://127.0.0.1:59999` – URL không thể kết nối.

### 6.3. Cách thực hiện

Do lệnh `integration.py --url` nhận một URL cho mỗi lần gọi, tạo một script riêng để đưa hai URL vào cùng một scan job.

Tạo file `create_partial_scan.py` tại thư mục gốc dự án:

```python
from pathlib import Path

from storage.db import create_scan_job, init_db


DB_PATH = Path(__file__).with_name("security_monitoring.db")

targets = [
    "http://127.0.0.1:5000/secure",
    "http://127.0.0.1:59999"
]

allowed_hosts = [
    "http://127.0.0.1:5000",
    "http://127.0.0.1:59999"
]


def main():
    init_db(DB_PATH)

    scan_id = create_scan_job(
        DB_PATH,
        targets,
        allowed_hosts
    )

    print("Đã tạo lượt quét PARTIAL:")
    print("Scan ID:", scan_id)
    print("URL 1:", targets[0])
    print("URL 2:", targets[1])


if __name__ == "__main__":
    main()
```

Chạy script:

```powershell
python create_partial_scan.py
```

Worker xử lý job; theo dõi log và trạng thái trên Dashboard.

### 6.4. Kết quả thực tế

- Scan ID: `40b5d9d8-96c2-437e-89d4-4b85fc544f7f`
- Trạng thái: `Hoàn tất một phần (PARTIAL)`
- Tổng URL: `2`
- URL hoàn tất: `1`
- URL thất bại: `1`

Log Worker:

```text
Processing scan: 40b5d9d8-96c2-437e-89d4-4b85fc544f7f
Progress: 1/2 - http://127.0.0.1:5000/secure - completed
Progress: 2/2 - http://127.0.0.1:59999 - failed
Scan finished: partial
Summary: {'total': 2, 'completed': 1, 'failed': 1}
```

### 6.5. Nhận xét

Worker xử lý thành công URL `/secure`, đồng thời ghi nhận lỗi kết nối đối với URL sử dụng cổng `59999`. Vì chỉ có một trong hai URL hoàn tất nên trạng thái tổng hợp của lượt quét là PARTIAL.

### 6.6. Bằng chứng

Kết quả kiểm thử tự động cho ca PARTIAL được lưu trong [log nghiệm thu](docs/week6_scanner_results.txt).

## 7. Kiểm thử Redirect ngoài phạm vi

### 7.1. Mục tiêu

Kiểm tra Scanner có nhận được phản hồi HTTP redirect hay không, đồng thời xác nhận Scanner không truy cập đến URL redirect nằm ngoài phạm vi được cho phép.

### 7.2. Cấu hình và cách chạy

Bài test dựng hai HTTP server trên localhost với cổng trống do hệ điều hành cấp. Origin của máy chủ đầu tiên được cấp phép. Máy chủ này trả HTTP 302 tới máy chủ thứ hai nằm ngoài origin được cấp phép.

```powershell
python test_redirect.py
```

### 7.3. Điều kiện kiểm tra và kết quả

- Máy chủ nguồn nhận đúng một yêu cầu và trả HTTP 302.
- Máy chủ đích nhận 0 yêu cầu.
- Kết quả scanner có `status="failed"`, lỗi `Redirect target is outside allowed scope` và `redirect_count=0`.
- Theo schema hiện tại, kết quả lỗi có `status_code=None`. HTTP 302 được xác nhận từ máy chủ nguồn trong bài test.

Bài test có assertion cho từng điều kiện trên và tự báo lỗi nếu kết quả sai. [Log chạy thực tế](docs/week6_scanner_results.txt).

## 8. Tổng kết kết quả Week 6

| Hạng mục | Kết quả |
|---|---|
| Quét trực tiếp Web Demo | 3/3 URL hoàn tất |
| Tạo scan job qua Queue | Đã ghi nhận job và Worker xử lý |
| Dashboard | Hiển thị scan, URL, findings và alerts |
| HTTP 500 | URL được ghi nhận completed; lượt quét hoàn tất |
| FAILED | 0/1 URL thành công; lượt quét thất bại |
| PARTIAL | 1/2 URL hoàn tất; lượt quét hoàn tất một phần |
| Redirect ngoài scope | Nhận HTTP 302 và chặn đích ngoài phạm vi |

## 9. Kết luận

Qua các kiểm thử trong tuần 6, hệ thống đã thể hiện được luồng quét trực tiếp, xử lý scan job thông qua Queue và Worker, đồng thời hiển thị kết quả trên Dashboard.

Các tình huống HTTP 500, FAILED và PARTIAL cho thấy hệ thống phân biệt được phản hồi HTTP từ máy chủ với lỗi không thể kết nối và tổng hợp trạng thái cho lượt quét có nhiều URL.

Bài kiểm thử redirect cũng xác nhận Scanner nhận được HTTP 302 từ URL ban đầu và chặn đích redirect nằm ngoài phạm vi cho phép.

Các mã lượt quét trong báo cáo là bản ghi do thành viên bàn giao. Bốn ca lỗi và chuyển hướng đã được chạy lại tự động trên Windows với cơ sở dữ liệu tạm, có kết quả tại [log nghiệm thu](docs/week6_scanner_results.txt).

## 10. Chạy lại bộ nghiệm thu của bộ quét

Từ thư mục gốc dự án, chạy:

```powershell
python -X utf8 -m unittest test_redirect tests.test_scanner_week6 -v
python -m pytest -q
```

Bộ nghiệm thu tự dựng web localhost trên cổng trống và tạo SQLite tạm. Có thể chạy lại mà không cần khởi động worker hoặc web demo riêng.
