# Thành viên 1 — Trưởng nhóm và Dashboard Streamlit

[Bảng phân công và hợp đồng dữ liệu](../../PHAN_CONG.md)

Bạn phụ trách **dashboard và điều phối nhóm** trong phương án Web Scanner + Dashboard + Alert System. Dùng web thử nghiệm cục bộ và dữ liệu mô phỏng khi làm demo.

## Việc cần làm theo tuần

| Tuần | Việc cần làm |
|---|---|
| **1** | Chốt tiêu chí nghiệm thu, phác thảo trang Tổng quan, Lượt quét, Phát hiện và Cảnh báo. |
| **2** | Tái sử dụng bố cục Streamlit và bộ lọc, chuyển sang dữ liệu mẫu về lượt quét, phát hiện và cảnh báo web. |
| **3** | Kết nối SQLite, cho chọn mục tiêu đã cấu hình để tạo lượt quét, hiển thị kết quả và bằng chứng. |
| **4** | Hiển thị trạng thái lượt quét, lịch sử cảnh báo và thao tác xác nhận hoặc xử lý cảnh báo. |
| **5** | Kiểm thử giao diện với lượt quét thành công, kết quả trống và lượt quét lỗi. Điều phối sửa lỗi tích hợp. |
| **6** | Điều phối demo và trình bày luồng từ tạo lượt quét đến xem cảnh báo trên dashboard. |

## Bắt đầu tuần 2

1. Dùng dashboard Streamlit hiện có trong thư mục làm việc (`dashboard/app.py`) làm nền cho bố cục và bộ lọc. Tạo dữ liệu mẫu theo bảng dữ liệu trong kế hoạch mới.
2. Dựng bảng lịch sử lượt quét và bảng phát hiện. Mỗi phát hiện hiển thị URL, quy tắc, mức độ và bằng chứng rút gọn.
3. Thêm bộ lọc theo thời gian, mục tiêu và mức độ. Đối chiếu số lượt quét, phát hiện và cảnh báo với dữ liệu mẫu, kể cả ca có lượt quét nhưng không có phát hiện.
4. Chốt với thành viên 3 cách đọc lịch sử, tạo yêu cầu quét và cập nhật trạng thái cảnh báo. Thống nhất nhãn cho các lượt quét lỗi và chưa hoàn tất.

## Bàn giao

Gửi ảnh hoặc bản chạy dashboard mẫu và số liệu kỳ vọng cho thành viên 5. Nhận dữ liệu quét mẫu từ thành viên 2 và 4, giao diện truy vấn từ thành viên 3.
