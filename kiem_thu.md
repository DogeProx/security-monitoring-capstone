# TUẦN 6 – DEMO VÀ KIỂM THỬ BỘ QUÉT WEB SECURITY SCANNER

## 1. Mục tiêu

Tuần 6 tập trung thực hiện demo hệ thống Automated Web Security Scanner trên môi trường website thử nghiệm do nhóm xây dựng.

Các mục tiêu chính:

- Khởi động website thử nghiệm phục vụ quá trình quét.
- Chạy bộ Scanner trực tiếp để kiểm tra khả năng thu thập thông tin và phát hiện cấu hình bảo mật chưa an toàn.
- Khởi động Worker để xử lý các lượt quét trong hàng đợi.
- Kiểm tra cơ chế đưa lượt quét vào Queue.
- Khởi động Dashboard để theo dõi kết quả.
- Kiểm tra thông tin lượt quét, trạng thái xử lý, findings và alerts.
- Giải thích ý nghĩa các trạng thái của một lượt quét dựa trên kết quả thực tế.

## 2. Môi trường kiểm thử

| Thành phần | Thông tin |
|---|---|
| Hệ điều hành | Windows |
| Ngôn ngữ | Python |
| Môi trường | Virtual Environment (`.venv`) |
| Website thử nghiệm | Web Demo ATTT |
| Địa chỉ website | `http://127.0.0.1:5000` |
| Dashboard | Streamlit |
| Địa chỉ Dashboard | `http://127.0.0.1:8501` |
| Database | SQLite |
| Các thành phần xử lý | Scanner, Worker, Queue, Dashboard |

Website thử nghiệm được xây dựng trong thư mục `Web_demo`, cung cấp 7 endpoint phục vụ kiểm thử các tình huống bảo mật khác nhau.

## 3. Triển khai môi trường demo

### 3.1. Khởi động website thử nghiệm

Tại thư mục gốc dự án, mở một terminal và chạy:

```powershell
python -X utf8 Web_demo/app.py
```

Kết quả ghi nhận:

```text
Web Demo ATTT đã sẵn sàng (7 Endpoints)!
Truy cập giao diện tại: http://127.0.0.1:5000
```

Truy cập địa chỉ `http://127.0.0.1:5000` bằng trình duyệt để kiểm tra giao diện website thử nghiệm.

Các endpoint hiển thị trên giao diện gồm:

- `/secure`
- `/vuln-headers`
- `/vuln-cookie`
- `/vuln-multi`
- `/public-page`
- `/api/data`
- `/error`

Trong đó, các endpoint `/secure`, `/vuln-headers` và `/vuln-cookie` được sử dụng trong lượt quét trực tiếp được ghi nhận ở phần tiếp theo.

### 3.2. Chạy Scanner trực tiếp

Mở terminal khác tại thư mục gốc dự án và chạy:

```powershell
python integration.py
```

Kết quả thực tế:

```text
Processing scan: 6896a22a-ee01-46a3-b339-a7138e62d93b

Progress: 1/3 - http://127.0.0.1:5000/secure - completed
Progress: 2/3 - http://127.0.0.1:5000/vuln-headers - completed
Progress: 3/3 - http://127.0.0.1:5000/vuln-cookie - completed

Scan finished: completed
Summary: {'total': 3, 'completed': 3, 'failed': 0}

Mã lượt quét: 6896a22a-ee01-46a3-b339-a7138e62d93b
Trạng thái: completed
```

**Kết quả:**

- Tổng số URL được kiểm tra: 3.
- Số URL xử lý thành công: 3.
- Số URL thất bại: 0.
- Trạng thái tổng thể: `completed`.

Điều này chứng minh Scanner có thể thực hiện lượt quét trên các endpoint thử nghiệm và hoàn thành quá trình xử lý cả 3 URL.

### 3.3. Khởi động Worker

Mở một terminal khác và chạy:

```powershell
python worker.py
```

Kết quả ghi nhận:

```text
Worker started.
Recovered jobs: 1
```

Sau khi khởi động, Worker tiếp nhận và xử lý các lượt quét đang chờ trong hàng đợi.

Các log thực tế thể hiện:

```text
Processing scan: <scan_id>

Progress: 1/3 - http://127.0.0.1:5000/secure - completed
Progress: 2/3 - http://127.0.0.1:5000/vuln-headers - completed
Progress: 3/3 - http://127.0.0.1:5000/vuln-cookie - completed

Scan finished: completed
Summary: {'total': 3, 'completed': 3, 'failed': 0}
```

Log cũng ghi nhận nhiều lượt quét được Worker xử lý liên tiếp.

**Ý nghĩa:**

- Worker được khởi động độc lập với Dashboard.
- Worker ghi nhận có 1 job được phục hồi khi khởi động (`Recovered jobs: 1`).
- Worker tiếp tục xử lý các lượt quét và cập nhật tiến trình theo từng URL.
- Các lượt quét hiển thị trong log đều có 3 URL hoàn thành, không có URL thất bại.

### 3.4. Đưa lượt quét vào hàng đợi

Sử dụng terminal khác để chạy:

```powershell
python integration.py --enqueue
```

Kết quả:

```text
Đã tạo yêu cầu quét: 73e3c28e-33f9-4c02-8bec-c6e24a5e154d
```

Lệnh này thực hiện thao tác tạo yêu cầu quét và đưa yêu cầu vào hàng đợi để Worker xử lý.

Đây là bước minh họa cơ chế tách biệt giữa việc tạo yêu cầu quét và quá trình thực thi lượt quét.

### 3.5. Khởi động Dashboard

Mở terminal khác và chạy:

```powershell
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Kết quả:

```text
You can now view your Streamlit app in your browser.

URL: http://127.0.0.1:8501
```

Truy cập:

`http://127.0.0.1:8501`

Dashboard cung cấp giao diện theo dõi các lượt quét, findings và alerts.

## 4. Kết quả kiểm thử trên Dashboard

### 4.1. Tổng quan hệ thống

Tại thời điểm chụp bằng chứng, Dashboard hiển thị:

| Chỉ số | Giá trị |
|---|---:|
| Lượt quét | 113 |
| Tổng URL yêu cầu | 319 |
| Phát hiện | 403 |
| Cảnh báo | 79 |

Các số liệu trên là số liệu tổng quan được Dashboard hiển thị tại thời điểm chụp, không phải số liệu riêng của một lượt quét.

Dashboard hỗ trợ lọc theo:

- Khoảng ngày tạo lượt quét.
- Mục tiêu.
- Mức độ nghiêm trọng.

Ngoài ra, giao diện có các tab:

- Lượt quét.
- Phát hiện.
- Cảnh báo.

### 4.2. Kiểm tra thông tin một lượt quét

Lượt quét được sử dụng làm bằng chứng:

`6896a22a-ee01-46a3-b339-a7138e62d93b`

Thông tin hiển thị:

| Thuộc tính | Giá trị |
|---|---|
| Mã lượt quét | `6896a22a-ee01-46a3-b339-a7138e62d93b` |
| Mục tiêu | `/secure`, `/vuln-headers`, `/vuln-cookie` |
| Thời điểm tạo | 20/11/2026 23:23:18 |
| Thời điểm kết thúc | 20/11/2026 23:23:18 |
| Trạng thái | Hoàn tất |
| URL thành công | 3 |
| Tổng URL | 3 |
| Thông tin lỗi | Không có |

Kết quả cho thấy lượt quét hoàn thành đầy đủ cả 3 URL mục tiêu.

### 4.3. Kiểm tra các phát hiện bảo mật

Dashboard hiển thị các findings được liên kết với lượt quét trên.

| Mã phát hiện | URL | Quy tắc | Mức độ | Bằng chứng |
|---|---|---|---|---|
| 406 | `/vuln-cookie` | `SEC-CKI-HTTPONLY` | Cao | Cookie `session_id` thiếu cờ HttpOnly |
| 405 | `/vuln-cookie` | `SEC-HDR-XCTO` | Thấp | Thiếu X-Content-Type-Options |
| 404 | `/vuln-cookie` | `SEC-HDR-CSP` | Trung bình | Thiếu Content-Security-Policy |
| 403 | `/vuln-headers` | `SEC-HDR-XCTO` | Thấp | Thiếu X-Content-Type-Options |
| 402 | `/vuln-headers` | `SEC-HDR-CSP` | Trung bình | Thiếu Content-Security-Policy |

**Phân tích kết quả:**

1. `SEC-CKI-HTTPONLY`: Phát hiện cookie phiên `session_id` không có thuộc tính HttpOnly. Điều này làm tăng nguy cơ cookie bị truy cập thông qua JavaScript khi xảy ra lỗ hổng XSS.
2. `SEC-HDR-XCTO`: Phát hiện máy chủ không trả về header `X-Content-Type-Options: nosniff`, làm giảm khả năng ngăn trình duyệt tự suy đoán kiểu nội dung.
3. `SEC-HDR-CSP`: Phát hiện thiếu header Content-Security-Policy, khiến website thiếu một lớp kiểm soát nguồn tài nguyên được phép tải và thực thi.

Dashboard hiển thị cả mã quy tắc, mức độ, bằng chứng và hướng khắc phục cho từng phát hiện.

## 5. Giải thích các trạng thái lượt quét

Trong quá trình demo, cần phân biệt trạng thái của một lượt quét với trạng thái xử lý của từng URL.

### 5.1. Trạng thái `PENDING`

Lượt quét đã được tạo và đang chờ Worker tiếp nhận xử lý.

Đây là trạng thái có ý nghĩa trong cơ chế Queue: hệ thống đã ghi nhận yêu cầu nhưng quá trình quét chưa bắt đầu.

### 5.2. Trạng thái `RUNNING`

Worker đã tiếp nhận lượt quét và đang thực hiện các công việc kiểm tra.

Trong terminal, trạng thái này được thể hiện thông qua log `Processing scan` và các dòng `Progress` khi Worker xử lý từng URL.

### 5.3. Trạng thái `COMPLETED`

Lượt quét kết thúc bình thường.

Trong bằng chứng thực tế:

```text
Summary: {'total': 3, 'completed': 3, 'failed': 0}
Trạng thái: completed
```

Điều đó có nghĩa cả 3 URL đều được xử lý thành công.

Lưu ý: `COMPLETED` không đồng nghĩa website an toàn. Một lượt quét có thể hoàn thành bình thường nhưng vẫn phát hiện nhiều vấn đề bảo mật.

### 5.4. Trạng thái `FAILED`

Lượt quét thất bại do lỗi nghiêm trọng trong quá trình xử lý.

Cần phân biệt trạng thái này với trường hợp một website có phát hiện bảo mật. Việc phát hiện thiếu security header không khiến lượt quét trở thành `FAILED`.

### 5.5. Trạng thái `PARTIAL`

Lượt quét hoàn thành một phần, nhưng có URL hoặc công việc không xử lý thành công.

Ví dụ về mặt ý nghĩa: một lượt quét có 3 URL, trong đó 2 URL được xử lý thành công và 1 URL thất bại.

**Lưu ý:** Các trạng thái trên cần được đối chiếu với logic cập nhật trạng thái trong code của dự án. Bằng chứng tuần 6 hiện tại trực tiếp thể hiện trạng thái `completed`; chưa có ảnh log chứng minh lượt quét thực tế đạt `FAILED` hoặc `PARTIAL`.

## 6. Đánh giá kết quả kiểm thử

| Hạng mục | Kết quả ghi nhận | Đánh giá |
|---|---|---|
| Khởi động Web Demo | Website chạy tại port 5000, hiển thị 7 endpoint | Đạt |
| Scanner trực tiếp | 3/3 URL hoàn thành | Đạt |
| Worker | Khởi động và xử lý các lượt quét | Đạt |
| Job Recovery | Ghi nhận `Recovered jobs: 1` | Đạt |
| Queue | Tạo yêu cầu quét thành công | Đạt |
| Dashboard | Khởi động tại port 8501 | Đạt |
| Hiển thị lịch sử quét | Hiển thị mã lượt quét, mục tiêu, thời gian và trạng thái | Đạt |
| Phát hiện bảo mật | Hiển thị các findings về CSP, XCTO và HttpOnly | Đạt |
| Hiển thị cảnh báo | Dashboard có tab và số liệu cảnh báo | Đạt |
| Kiểm thử endpoint HTTP 500 | Có endpoint `/error` trên Web Demo, nhưng chưa có bằng chứng Scanner đã quét endpoint này | Chưa xác nhận |
| Kiểm thử trạng thái FAILED/PARTIAL | Chưa có bằng chứng lượt quét thực tế ở hai trạng thái này | Chưa xác nhận |

## 7. Kết luận tuần 6

Qua quá trình demo và kiểm thử, hệ thống Automated Web Security Scanner đã thể hiện được luồng hoạt động chính:

1. Website thử nghiệm được khởi động và cung cấp các endpoint phục vụ kiểm thử.
2. Scanner thực hiện quét trực tiếp trên các mục tiêu được cấu hình.
3. Worker có khả năng tiếp nhận và xử lý các lượt quét thông qua hàng đợi.
4. Hệ thống ghi nhận mã lượt quét và tiến trình xử lý từng URL.
5. Dashboard hiển thị lịch sử quét, trạng thái, các phát hiện và cảnh báo.
6. Các phát hiện về thiếu security headers và thuộc tính HttpOnly được hiển thị kèm bằng chứng và hướng khắc phục.

Lượt quét trực tiếp có mã `6896a22a-ee01-46a3-b339-a7138e62d93b` đã hoàn thành 3/3 URL, không có URL thất bại. Dashboard cũng hiển thị các phát hiện tương ứng với hai endpoint `/vuln-headers` và `/vuln-cookie`.

Nhìn chung, các bằng chứng hiện có xác nhận được hoạt động cơ bản của Scanner, Worker, Queue, Database và Dashboard trong luồng demo.

Các tình huống HTTP 500, FAILED và PARTIAL cần được kiểm thử bổ sung trước khi kết luận toàn bộ các trường hợp lỗi đã được nghiệm thu.