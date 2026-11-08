# Thành viên 3 — SQLite và Alert System

[Bảng phân công và hợp đồng dữ liệu](../../PHAN_CONG.md)

Bạn phụ trách **lưu dữ liệu và quản lý vòng đời cảnh báo** trong phương án Web Scanner + Dashboard + Alert System. Dùng web thử nghiệm cục bộ và dữ liệu mô phỏng khi làm demo.

## Việc cần làm theo tuần

| Tuần | Việc cần làm |
|---|---|
| **1** | Thiết kế dữ liệu mục tiêu, lượt quét, phát hiện, cảnh báo và lịch sử thao tác. |
| **2** | Tạo SQLite và hàm tạo, đọc lượt quét cùng hàm ghi, truy vấn phát hiện mẫu. |
| **3** | Tạo cảnh báo tự động từ phát hiện đạt ngưỡng cấu hình. Liên kết lượt quét, phát hiện và cảnh báo để truy vết. |
| **4** | Bổ sung trạng thái đã xem, đã xử lý, lịch sử thao tác và phối hợp lưu trạng thái worker. |
| **5** | Kiểm thử chạy lại cùng dữ liệu, ghi đồng thời, tạo cảnh báo trùng và chuyển trạng thái. |
| **6** | Demo mở bằng chứng của một cảnh báo, xử lý cảnh báo và tra lại lịch sử. |

## Bắt đầu tuần 2

1. Dùng cơ sở dữ liệu tạm để kiểm thử. Viết hàm khởi tạo SQLite có thể gọi lại và thiết lập khóa nối giữa lượt quét, phát hiện và cảnh báo.
2. Viết hàm tạo yêu cầu quét, lưu phát hiện và truy vấn theo mục tiêu, ngày hoặc mức độ. Thống nhất tên trường với thành viên 1, 2 và 4.
3. Giữ một phát hiện theo cặp URL và quy tắc trong cùng lượt quét. Viết kiểm thử ghi lại cùng dữ liệu để chuẩn bị cho việc tạo cảnh báo ở tuần 3.
4. Chuẩn bị dữ liệu mẫu có một lượt quét với phát hiện và một lượt quét sạch. Kiểm tra đọc lại sau khi mở kết nối mới.

## Bàn giao

Bàn giao cách gọi hàm ghi cho thành viên 2, cách đọc và cập nhật trạng thái cho thành viên 1, cách đọc báo cáo cho thành viên 5.
