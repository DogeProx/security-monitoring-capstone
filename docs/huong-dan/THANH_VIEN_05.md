# Thành viên 5 — Web demo, báo cáo và kiểm thử tích hợp

[Bảng phân công và hợp đồng dữ liệu](../../PHAN_CONG.md)

Bạn phụ trách **môi trường thử nghiệm, xuất báo cáo và bàn giao** trong phương án Web Scanner + Dashboard + Alert System. Dùng web thử nghiệm cục bộ và dữ liệu mô phỏng khi làm demo.

## Việc cần làm theo tuần

| Tuần | Việc cần làm |
|---|---|
| **1** | Thiết kế web demo cục bộ, danh sách tình huống và cột báo cáo CSV/HTML. |
| **2** | Dựng trang có header đúng, trang cố ý thiếu header và phản hồi đặt cookie demo. Viết chức năng xuất báo cáo mẫu. |
| **3** | Kiểm thử luồng quét, ghi phát hiện, tạo cảnh báo và xuất báo cáo từ SQLite. |
| **4** | Thử các ca web demo không chạy, trang sạch và lượt quét có nhiều phát hiện. Hoàn thiện bộ dữ liệu demo. |
| **5** | Chạy thử trên Windows và Linux, tổng hợp README, kết quả kiểm thử và lỗi còn lại. |
| **6** | Trình bày báo cáo CSV/HTML và kiểm tra quy trình demo từ bản cài mới. |

## Bắt đầu tuần 2

1. Dựng web demo cục bộ với tối thiểu một trang HTML đủ header và một trang cố ý thiếu header. Tạo một phản hồi có cookie phiên giả để thử quy tắc HttpOnly.
2. Ghi bảng URL và phát hiện kỳ vọng cho từng trang, gồm trang sạch và trang có nhiều phát hiện. Chia sẻ cho thành viên 2 và 4 để thử cùng một bộ ca.
3. Xuất báo cáo mẫu với thời điểm, mục tiêu, URL, quy tắc, mức độ, bằng chứng rút gọn, khuyến nghị và trạng thái cảnh báo.
4. Kiểm tra CSV và HTML với tiếng Việt, ký tự đặc biệt và danh sách rỗng. Đối chiếu số hàng và nội dung với dữ liệu đầu vào.

## Bàn giao

Gửi hướng dẫn chạy web demo và các kết quả kỳ vọng cho cả nhóm. Nhận dữ liệu báo cáo từ thành viên 3 và chốt thứ tự demo với trưởng nhóm.
