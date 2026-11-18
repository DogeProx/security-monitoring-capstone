# Tiến độ dự án · 18/11/2026

Các mốc dưới đây dựa trên đầu ra của [kế hoạch 6 tuần](PHAN_CONG.md) và bản tích hợp trên `main`. Tuần hiện tại là mốc thành viên đang thực hiện hoặc còn cần nghiệm thu.

| Thành viên | Tuần hiện tại | Đầu ra đã tích hợp và việc còn lại |
|---|---|---|
| **Lê Đăng Khoa** | **Tuần 6** | Đã kiểm thử dashboard với dữ liệu trống, lượt quét thành công và lỗi. Kịch bản và phân vai đã sẵn sàng. Còn tổng duyệt với cả nhóm từ bản cài mới. |
| **Lê Nguyễn Thanh Quang** | **Tuần 5** | Bộ quét, worker và scheduler đã tích hợp. Đã kiểm tra chuyển hướng, timeout, chống tạo lượt trùng và worker chạy theo lịch khi dashboard tắt. Còn xác nhận ca máy chủ trả mã lỗi. |
| **Trương Đức Nguyên** | **Tuần 5** | SQLite đã lưu kết quả và lịch sử cảnh báo. Ba hàm truy vấn bổ sung đã được kiểm tra với dữ liệu mẫu. Bài kiểm thử xác nhận nhiều kết nối ghi song song không tạo trùng phát hiện hoặc cảnh báo. Còn chạy thử nhiều tiến trình và nghiệm thu phần trình bày lịch sử. |
| **Phan Tuấn Tài** | **Tuần 5** | Đã tích hợp ba quy tắc, cấu hình bật/tắt trong worker và kiểm thử JSON, trang sạch, trang thiếu cấu hình và trang không đặt cookie phiên. Còn tổng hợp đối chiếu mức độ từng quy tắc với ngưỡng cảnh báo cho phần trình bày. |
| **Vũ Đắc Lộc** | **Tuần 5** | Web demo, ca biên và xuất CSV/HTML từ SQLite đã qua kiểm thử trên Windows. Còn xác nhận trên Linux và chạy lại quy trình từ bản cài mới. |

[Kịch bản tổng duyệt và kết quả kiểm thử dashboard](TUAN_5_6_NGHIEM_THU_VA_DEMO.md).
