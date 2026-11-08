# Thành viên 2 — Bộ quét web và thực thi lượt quét

[Bảng phân công và hợp đồng dữ liệu](../../PHAN_CONG.md)

Bạn phụ trách **thu thập phản hồi http và tiến trình quét** trong phương án Web Scanner + Dashboard + Alert System. Dùng web thử nghiệm cục bộ và dữ liệu mô phỏng khi làm demo.

## Việc cần làm theo tuần

| Tuần | Việc cần làm |
|---|---|
| **1** | Chốt danh sách mục tiêu, phạm vi URL, giới hạn lượt quét và cấu trúc phản hồi HTTP chuẩn hóa. |
| **2** | Viết bộ quét GET cho danh sách URL demo. Thu mã HTTP và header, xử lý timeout và kiểm tra phạm vi trước mỗi yêu cầu. |
| **3** | Gọi bộ quy tắc của thành viên 4, ghi phát hiện và cập nhật tiến độ lượt quét qua thành viên 3. |
| **4** | Chạy worker tách khỏi Streamlit, nhận yêu cầu quét và hỗ trợ lịch quét theo cấu hình. |
| **5** | Kiểm thử URL ngoài phạm vi, redirect, timeout, trang lỗi và việc lượt quét tiếp tục khi dashboard tắt. |
| **6** | Demo chạy bộ quét trên web thử nghiệm và giải thích các trạng thái lượt quét. |

## Bắt đầu tuần 2

1. Nhận một mục tiêu từ danh sách cấu hình và các đường dẫn demo. Mặc định dùng web cục bộ do nhóm kiểm soát.
2. Xác thực scheme, host và port theo cấu hình trước khi gửi yêu cầu. Chỉ theo redirect nếu đích nằm trong phạm vi và còn trong giới hạn lượt quét.
3. Chuẩn hóa URL cuối, mã HTTP, loại nội dung và các header cần thiết. Giữ riêng từng dòng Set-Cookie để bộ quy tắc kiểm tra thuộc tính.
4. Đặt timeout và giới hạn số trang, redirect. Trả lỗi theo từng URL để một trang gặp lỗi vẫn cho phép xử lý những trang còn lại.

## Bàn giao

Gửi thành viên 4 cấu trúc phản hồi và mẫu có nhiều header Set-Cookie. Gửi thành viên 3 trạng thái, tiến độ và lỗi rút gọn. Dùng mục tiêu demo do thành viên 5 chuẩn bị.
