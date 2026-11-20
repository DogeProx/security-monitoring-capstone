# Nghiệm thu tuần 5 và kịch bản demo tuần 6

**Phụ trách** · Lê Đăng Khoa — Trưởng nhóm và Dashboard

**Phạm vi** · Dashboard Streamlit và luồng tích hợp trên localhost

## Tuần 5 · Kết quả kiểm thử giao diện

| Tình huống | Kết quả trên dashboard |
|---|---|
| Cơ sở dữ liệu mới | Hiện thông báo chưa có lượt quét và vẫn cho phép tạo yêu cầu đầu tiên. |
| Quét trang `/secure` | 1 URL thành công, 0 phát hiện, 0 cảnh báo. Hai tab tương ứng hiển thị trạng thái trống. |
| Quét cả ba trang demo chính | 3 URL thành công, 5 phát hiện và 1 cảnh báo mức Cao. Mở được bằng chứng thiếu `HttpOnly` và hướng khắc phục. |
| Web demo không hoạt động | Lượt quét chuyển thành **Thất bại**, có chi tiết lỗi, 0 phát hiện và 0 cảnh báo. |
| Xử lý cảnh báo | Bấm **Xác nhận đã xem**, rồi **Đánh dấu đã xử lý**. Dashboard hiển thị lịch sử sau mỗi thao tác. |

Trong ca mất kết nối, worker đã được sửa để lưu lỗi đầu tiên của lượt quét cùng trạng thái tổng hợp. Dashboard đọc chi tiết này từ SQLite. Các ca trên chạy bằng Streamlit AppTest với SQLite tạm và web demo cục bộ.

```text
python -m unittest tests.test_dashboard -v
```

## Tuần 6 · Kịch bản trình bày

### Chuẩn bị và phân vai

Từ một bản clone mới của bản bàn giao, cài thư viện theo [README](README.md#chạy-demo-tích-hợp). Giữ ba terminal mở và chạy một lệnh trong mỗi terminal.

| Terminal | Lệnh |
|---|---|
| Web demo | `python -X utf8 Web_demo/app.py` |
| Worker | `python -X utf8 worker.py` |
| Dashboard | `python -m streamlit run dashboard/app.py --server.address 127.0.0.1` |

Mở [dashboard cục bộ](http://127.0.0.1:8501). Dùng cơ sở dữ liệu mới để số liệu tổng quan khớp kịch bản. Nếu đã có dữ liệu, mở lượt quét mới theo mã vừa tạo.

### Thứ tự trình bày

1. **Khoa** giới thiệu mục tiêu đồ án, chọn **Tất cả trang demo** và bấm **Đưa vào hàng đợi**. Ghi lại mã lượt quét.
2. **Quang** giải thích worker nhận yêu cầu từ SQLite. Khi worker báo `Scan finished`, Khoa bấm **Tải lại kết quả** và mở lượt vừa tạo để chỉ ra **3/3 URL thành công**.
3. **Tài** mở tab **Phát hiện**. So sánh trang sạch với các trang thiếu cấu hình, sau đó giải thích bằng chứng thiếu `HttpOnly` và hướng khắc phục.
4. **Nguyên** mở tab **Cảnh báo**. Với cơ sở dữ liệu mới, tổng quan hiển thị **1 lượt quét, 3 URL, 5 phát hiện và 1 cảnh báo**. Bấm **Xác nhận đã xem**, rồi **Đánh dấu đã xử lý** và kiểm tra lịch sử.
5. **Lộc** xuất CSV và HTML bằng lệnh trong README. Đối chiếu số phát hiện và trạng thái cảnh báo với dashboard.

Nếu lượt quét còn **Đang chờ**, kiểm tra terminal worker và bấm **Tải lại kết quả** sau khi worker hoàn tất. Nếu lượt quét **Thất bại**, mở **Thông tin lỗi** và kiểm tra web demo trên cổng 5000 trước khi tạo lượt mới.

### Bàn giao

Trưởng nhóm ghi lại commit dùng để demo, mã lượt quét và kết quả từng bước. Khi chạy thử cùng nhóm từ bản cài mới, đối chiếu báo cáo với chính lượt quét đã trình bày trước khi xác nhận buổi bàn giao.

---

## Nghiệm thu tuần 5 và đối chiếu báo cáo tuần 6 · Web demo và Reporter

**Phụ trách** · Vũ Đắc Lộc — Web demo, Báo cáo và Kiểm thử tích hợp

**Phạm vi** · Các endpoint kiểm thử cục bộ, xuất CSV/HTML từ SQLite và tương thích Windows/Linux

### Tuần 5 · Kết quả kiểm thử đa nền tảng và ca biên

| Tình huống | Kết quả kiểm chứng |
|---|---|
| Bảy endpoint của web demo | Phản hồi đúng mã trạng thái và cấu hình mẫu trên `/secure`, `/vuln-headers`, `/vuln-cookie`, `/vuln-multi`, `/api/data`, `/public-page` và `/error`. |
| Phản hồi API JSON (`/api/data`) | Bộ quy tắc bỏ qua kiểm tra CSP trên dữ liệu JSON, không tạo phát hiện sai. |
| Cơ sở dữ liệu trống hoặc không có lỗi | Xuất CSV và HTML thành công với 0 dòng dữ liệu, không phát sinh ngoại lệ. |
| Chèn mã HTML trong header/cookie | Toàn bộ cột bằng chứng trong `report.html` được thoát ký tự qua `html.escape`, không thực thi mã. |
| Tương thích Windows và Linux (WSL) | Đạt toàn bộ kiểm thử hồi quy, tích hợp tuần 3, ca biên tuần 4 và giao diện dashboard trên cả hai môi trường. |

Bộ xuất báo cáo (`Reporter/Export.py` và `Reporter/sqlite_exporter.py`) đã đồng bộ nhãn trạng thái cảnh báo tiếng Việt (`Mới`, `Đã xem`, `Đã xử lý`) với dashboard, bổ sung hướng dẫn khắc phục mặc định theo mã quy tắc và ghi tệp CSV theo bảng mã `utf-8-sig` để mở trực tiếp trên Excel không lỗi font.

```text
python -m unittest tests.test_demo_regressions tests.test_week3_integration tests.test_week4_edge_cases tests.test_dashboard -v