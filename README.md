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

## Chạy dashboard tuần 2

Dashboard tuần 2 hiển thị các lượt quét, phát hiện và cảnh báo mô phỏng. Bản mẫu đọc dữ liệu từ [sample_data.json](dashboard/sample_data.json).

Từ thư mục gốc của repo, chạy:

```text
python -m pip install -r dashboard/requirements.txt
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Mở `http://127.0.0.1:8501`. Màn hình mặc định có 4 lượt quét, 4 phát hiện và 2 cảnh báo. Thử lọc theo khoảng ngày, mục tiêu hoặc mức độ.
