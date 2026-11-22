# Automated Web Security Scanner with Dashboard + Alert System

Đồ án xây dựng công cụ tự động kiểm tra cấu hình bảo mật của ứng dụng web trong môi trường thử nghiệm. Bộ quét đọc phản hồi HTTP để ghi nhận các phát hiện, chẳng hạn header bảo mật bị thiếu hoặc cookie phiên thiếu thuộc tính bảo vệ. Dashboard giúp nhóm xem bằng chứng, theo dõi cảnh báo và xuất báo cáo.

## Phạm vi triển khai

| Thành phần | Chức năng |
|---|---|
| **Web Scanner** | Kiểm tra các URL đã cấu hình, thu thập phản hồi HTTP và ghi nhận kết quả từng lượt quét. |
| **Bộ quy tắc** | Kiểm tra Content Security Policy, X-Content-Type-Options và HttpOnly khi quy tắc áp dụng. Mỗi phát hiện có mức độ, bằng chứng và hướng khắc phục. |
| **Dashboard** | Hiển thị lịch sử lượt quét, phát hiện và cảnh báo. Người dùng có thể lọc kết quả theo mục tiêu, thời gian và mức độ. |
| **Alert System** | Tự tạo cảnh báo từ phát hiện đạt ngưỡng cấu hình, lưu trạng thái và lịch sử xử lý. |
| **Báo cáo** | Xuất kết quả quét, bằng chứng và trạng thái cảnh báo dưới dạng CSV và HTML. |

**Luồng demo dự kiến:** Chọn mục tiêu → chạy quét → lưu phát hiện → tạo cảnh báo → xem và xử lý trên dashboard → xuất báo cáo.

## Công nghệ dự kiến

- **Python 3.11+** cho bộ quét và bộ quy tắc.
- **Streamlit** cho dashboard.
- **SQLite** để lưu lượt quét, phát hiện, cảnh báo và lịch sử xử lý.

## Môi trường thử nghiệm

Nhóm demo trên ứng dụng web cục bộ do nhóm kiểm soát. Bộ quét dùng yêu cầu GET, giới hạn số trang, số lần chuyển hướng và thời gian chờ. Mục tiêu quét được xác định trước trong cấu hình.

## Kế hoạch thực hiện

Xem [bản phân công 6 tuần cho 5 thành viên](PHAN_CONG.md) và [thiết kế dashboard tuần 1](TUAN_1_THIET_KE_DASHBOARD.md).

Xem [tiến độ hiện tại của từng thành viên](PROGRESS.md).

## Chạy demo tích hợp

Chạy các lệnh dưới đây từ thư mục gốc của repo với Python 3.11 trở lên.

1. Cài thư viện.

   ```text
   python -m pip install -r dashboard/requirements.txt -r scanner/requirements.txt
   ```

2. Mở terminal thứ nhất và giữ web thử nghiệm chạy tại `http://127.0.0.1:5000`.

   ```text
   python -X utf8 Web_demo/app.py
   ```

3. Mở terminal thứ hai, quét ba trang demo rồi mở dashboard tại `http://127.0.0.1:8501`.

   ```text
   python integration.py
   python -m streamlit run dashboard/app.py --server.address 127.0.0.1
   ```

   Lượt quét ghi dữ liệu thật vào `security_monitoring.db`. Trong cơ sở dữ liệu mới, kết quả dự kiến là **1 lượt quét, 3 URL, 5 phát hiện và 1 cảnh báo mức Cao**. Trang `/secure` có 0 phát hiện. Chọn mức **Cao** để xem phát hiện thiếu `HttpOnly` và cảnh báo liên quan.

4. Xuất báo cáo từ SQLite trong terminal khác.

   ```text
   python -m Reporter.Export --database security_monitoring.db
   ```

   Lệnh tạo `report.csv` và `report.html` trong thư mục hiện tại. Báo cáo dùng thời gian UTC, dashboard hiển thị giờ Việt Nam.

### Chạy worker riêng

Giữ web demo hoạt động, chạy `python worker.py` trong một terminal rồi chạy `python integration.py --enqueue` trong terminal khác. Dùng một tiến trình worker cho cơ sở dữ liệu demo. Mở hoặc tải lại dashboard để xem kết quả sau khi worker xử lý.

### Tạo lượt quét và xử lý cảnh báo trên dashboard

Giữ web demo hoạt động và chạy `python worker.py`. Mở **Tạo lượt quét**, chọn **Trang demo** hoặc **Nhập URL** rồi bấm **Đưa vào hàng đợi**. Ví dụ nhập `http://127.0.0.1:5000/secure`. Dashboard tự chọn lượt vừa tạo và cập nhật trạng thái khi lượt đang chờ hoặc đang chạy.

Trong tab **Kết quả theo URL**, bảng **Mục tiêu** hiển thị mã HTTP và số phát hiện của từng URL. Chọn một dòng để lọc danh sách phát hiện bên cạnh, rồi chọn mức độ và mở một phát hiện để xem bằng chứng. Bỏ chọn dòng để xem lại tất cả URL trong lượt.

Để kiểm tra website bên ngoài, mở hoặc tạo tệp `dashboard_origins.txt` ở thư mục gốc của dự án. Ghi địa chỉ gốc của mỗi website bạn quản lý hoặc được phép kiểm tra trên một dòng. Ghi cả giao thức và cổng nếu dùng cổng riêng. Dòng bắt đầu bằng `#` là chú thích.

```text
https://web-cua-ban.example
```

Lưu tệp và tải lại dashboard. Chọn **Nhập URL** rồi nhập đường dẫn cần kiểm tra, ví dụ `https://web-cua-ban.example/trang-chu`. Nếu nhập tên miền hoặc đường dẫn thiếu giao thức, dashboard mặc định dùng HTTPS. Khi website dùng HTTP, nhập rõ `http://`.

Bạn cũng có thể cấu hình qua PowerShell trước khi mở dashboard. Dùng dấu phẩy để phân cách nhiều địa chỉ.

```powershell
$env:DASHBOARD_ALLOWED_ORIGINS = "https://web-cua-ban.example"
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Ở tab **Cảnh báo**, mở bản ghi để xem phát hiện, bằng chứng, cách khắc phục và lịch sử. Chọn **Xác nhận đã xem** hoặc **Đánh dấu đã xử lý**. Dashboard ghi mỗi lần chuyển trạng thái vào lịch sử SQLite.

### Cấu hình quy tắc trên worker

Để tắt một quy tắc cho các lượt quét do worker xử lý, khởi động worker với mã quy tắc tương ứng. Có thể lặp lại cờ `--disable-rule`. Khi chạy worker với cấu hình mặc định, cả ba quy tắc đều bật.

```text
python -X utf8 worker.py --disable-rule SEC-HDR-CSP
```

Xem [kết quả kiểm thử dashboard và kịch bản bàn giao tuần 6](TUAN_5_6_NGHIEM_THU_VA_DEMO.md).

### Kiểm thử cục bộ

```text
python -m unittest scanner.test_client_edge_cases -v
python -m unittest detection_rules.test_rules -v
python -m unittest discover -s tests -v
python -m unittest test_scheduler -v
```
