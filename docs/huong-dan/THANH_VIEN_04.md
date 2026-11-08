# Thành viên 4 — Quy tắc phát hiện cấu hình web

[Bảng phân công và hợp đồng dữ liệu](../../PHAN_CONG.md)

Bạn phụ trách **phát hiện và phân mức độ từ phản hồi http** trong phương án Web Scanner + Dashboard + Alert System. Dùng web thử nghiệm cục bộ và dữ liệu mô phỏng khi làm demo.

## Việc cần làm theo tuần

| Tuần | Việc cần làm |
|---|---|
| **1** | Chốt bộ quy tắc, điều kiện áp dụng, mức độ minh họa và bằng chứng an toàn cho từng quy tắc. |
| **2** | Viết quy tắc kiểm tra CSP, X-Content-Type-Options và HttpOnly trên phản hồi mô phỏng. |
| **3** | Tích hợp quy tắc với bộ quét. Xuất phát hiện có mã quy tắc, mức độ, bằng chứng và cách khắc phục. |
| **4** | Thêm cấu hình bật tắt quy tắc và kiểm tra ca dễ báo sai, gồm API JSON và phản hồi không đặt cookie phiên. |
| **5** | Kiểm thử ca đạt, ca thiếu cấu hình và ca quy tắc không áp dụng. Đối chiếu mức độ với ngưỡng cảnh báo. |
| **6** | Demo so sánh một trang cấu hình đúng với một trang thiếu thiết lập và giải thích bằng chứng. |

## Bắt đầu tuần 2

1. Tách phần kiểm tra quy tắc khỏi HTTP client. Mỗi quy tắc nhận phản hồi chuẩn hóa và trả về phát hiện khi đủ điều kiện.
2. Với trang HTML demo, kiểm tra có header CSP áp dụng chính sách và giá trị X-Content-Type-Options là nosniff. Quy tắc CSP chỉ đánh giá sự hiện diện của header theo phạm vi demo.
3. Với cookie phiên có tên được cấu hình, kiểm tra HttpOnly trên từng dòng Set-Cookie phù hợp. Bằng chứng chỉ cần tên cookie và thuộc tính thiếu.
4. Viết ít nhất một ca đạt và một ca thiếu cấu hình cho từng quy tắc. Dùng mã quy tắc ổn định và mô tả cách khắc phục ngắn gọn.

## Bàn giao

Chốt định dạng phản hồi với thành viên 2. Gửi thành viên 3 và 5 danh sách mã quy tắc, mức độ và kết quả kỳ vọng.

[OWASP HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) · [OWASP Testing for Cookies Attributes](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes/)
