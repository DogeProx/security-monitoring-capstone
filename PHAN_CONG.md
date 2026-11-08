# Kế hoạch 6 tuần — Automated Web Security Scanner with Dashboard + Alert System

**Phương án 3 + 2 theo gợi ý của thầy.** Kế hoạch này hiểu Alert System là mô-đun tạo và quản lý cảnh báo từ kết quả quét web. Đây là giả định phạm vi cần đối chiếu nếu thầy yêu cầu một nguồn cảnh báo riêng.

**Link Source Code** · [DogeProx/security-monitoring-capstone](https://github.com/DogeProx/security-monitoring-capstone)

## Phạm vi và sản phẩm

- **Web Scanner** tự kiểm tra các URL đã cấu hình trên môi trường thử nghiệm được phép. Bản demo dùng web cục bộ, gửi GET trong phạm vi cho phép và giới hạn số trang, redirect, thời gian chờ.
- **Bộ quy tắc** kiểm tra cấu hình qua phản hồi HTTP. Ba ca minh họa gồm CSP và X-Content-Type-Options trên trang HTML, cùng thuộc tính HttpOnly trên cookie phiên demo. Mỗi phát hiện có mức độ, bằng chứng rút gọn và hướng khắc phục. [OWASP HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) · [OWASP Testing for Cookies Attributes](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes/)
- **Dashboard Streamlit** cho phép chọn mục tiêu đã cấu hình, yêu cầu quét và xem lịch sử lượt quét, phát hiện và cảnh báo. Bố cục và bộ lọc của bản mẫu dashboard đang có trong thư mục làm việc (`dashboard/app.py`) là nền để chuyển sang dữ liệu quét web ở tuần 2.
- **Alert System và báo cáo** lưu dữ liệu trong SQLite, tự tạo cảnh báo theo ngưỡng mức độ, ghi lịch sử xác nhận và xử lý, rồi xuất CSV và HTML.

Luồng demo chính: **chọn mục tiêu → quét → lưu phát hiện → tạo cảnh báo → xem và xử lý trên dashboard → xuất báo cáo**.

## Bảng phân công

| Tuần | Giai đoạn / Mục tiêu | Sản phẩm bàn giao | Thành viên 1 — Trưởng nhóm, Dashboard | Thành viên 2 — Bộ quét web | Thành viên 3 — SQLite và Alert System | Thành viên 4 — Quy tắc phát hiện | Thành viên 5 — Web demo, báo cáo và tích hợp |
|---|---|---|---|---|---|---|---|
| **1** | Thiết kế và chốt phạm vi | Sơ đồ luồng quét, hợp đồng dữ liệu, danh sách ca demo | Chốt tiêu chí nghiệm thu, phác thảo trang Tổng quan, Lượt quét, Phát hiện và Cảnh báo. | Chốt danh sách mục tiêu, phạm vi URL, giới hạn lượt quét và cấu trúc phản hồi HTTP chuẩn hóa. | Thiết kế dữ liệu mục tiêu, lượt quét, phát hiện, cảnh báo và lịch sử thao tác. | Chốt bộ quy tắc, điều kiện áp dụng, mức độ minh họa và bằng chứng an toàn cho từng quy tắc. | Thiết kế web demo cục bộ, danh sách tình huống và cột báo cáo CSV/HTML. |
| **2** | Dựng các thành phần cơ bản | Dashboard mẫu, bộ thu phản hồi HTTP, quy tắc, SQLite và báo cáo mẫu | Tái sử dụng bố cục Streamlit và bộ lọc, chuyển sang dữ liệu mẫu về lượt quét, phát hiện và cảnh báo web. | Viết bộ quét GET cho danh sách URL demo. Thu mã HTTP và header, xử lý timeout và kiểm tra phạm vi trước mỗi yêu cầu. | Tạo SQLite và hàm tạo, đọc lượt quét cùng hàm ghi, truy vấn phát hiện mẫu. | Viết quy tắc kiểm tra CSP, X-Content-Type-Options và HttpOnly trên phản hồi mô phỏng. | Dựng trang có header đúng, trang cố ý thiếu header và phản hồi đặt cookie demo. Viết chức năng xuất báo cáo mẫu. |
| **3** | Tích hợp từ quét đến cảnh báo | Một lượt quét trên web demo tạo phát hiện, tự sinh cảnh báo theo ngưỡng và hiển thị trên dashboard | Kết nối SQLite, cho chọn mục tiêu đã cấu hình để tạo lượt quét, hiển thị kết quả và bằng chứng. | Gọi bộ quy tắc của thành viên 4, ghi phát hiện và cập nhật tiến độ lượt quét qua thành viên 3. | Tạo cảnh báo tự động từ phát hiện đạt ngưỡng cấu hình. Liên kết lượt quét, phát hiện và cảnh báo để truy vết. | Tích hợp quy tắc với bộ quét. Xuất phát hiện có mã quy tắc, mức độ, bằng chứng và cách khắc phục. | Kiểm thử luồng quét, ghi phát hiện, tạo cảnh báo và xuất báo cáo từ SQLite. |
| **4** | Hoàn thiện vận hành | Worker độc lập, lịch quét cấu hình được, xử lý cảnh báo và xuất báo cáo từ SQLite | Hiển thị trạng thái lượt quét, lịch sử cảnh báo và thao tác xác nhận hoặc xử lý cảnh báo. | Chạy worker tách khỏi Streamlit, nhận yêu cầu quét và hỗ trợ lịch quét theo cấu hình. | Bổ sung trạng thái đã xem, đã xử lý, lịch sử thao tác và phối hợp lưu trạng thái worker. | Thêm cấu hình bật tắt quy tắc và kiểm tra ca dễ báo sai, gồm API JSON và phản hồi không đặt cookie phiên. | Thử các ca web demo không chạy, trang sạch và lượt quét có nhiều phát hiện. Hoàn thiện bộ dữ liệu demo. |
| **5** | Kiểm thử và sửa lỗi | Kết quả kiểm thử, dữ liệu demo và README cho Windows và Linux | Kiểm thử giao diện với lượt quét thành công, kết quả trống và lượt quét lỗi. Điều phối sửa lỗi tích hợp. | Kiểm thử URL ngoài phạm vi, redirect, timeout, trang lỗi và việc lượt quét tiếp tục khi dashboard tắt. | Kiểm thử chạy lại cùng dữ liệu, ghi đồng thời, tạo cảnh báo trùng và chuyển trạng thái. | Kiểm thử ca đạt, ca thiếu cấu hình và ca quy tắc không áp dụng. Đối chiếu mức độ với ngưỡng cảnh báo. | Chạy thử trên Windows và Linux, tổng hợp README, kết quả kiểm thử và lỗi còn lại. |
| **6** | Demo và bàn giao | Mã nguồn, kiểm thử, báo cáo mẫu và hướng dẫn chạy từ bản cài mới | Điều phối demo và trình bày luồng từ tạo lượt quét đến xem cảnh báo trên dashboard. | Demo chạy bộ quét trên web thử nghiệm và giải thích các trạng thái lượt quét. | Demo mở bằng chứng của một cảnh báo, xử lý cảnh báo và tra lại lịch sử. | Demo so sánh một trang cấu hình đúng với một trang thiếu thiết lập và giải thích bằng chứng. | Trình bày báo cáo CSV/HTML và kiểm tra quy trình demo từ bản cài mới. |

## Dữ liệu dùng chung cần chốt ở tuần 1

| Đối tượng | Trường tối thiểu | Đầu mối |
|---|---|---|
| Lượt quét | `scan_id`, mục tiêu, thời điểm tạo và kết thúc, trạng thái, số trang đã thử, thông tin lỗi rút gọn | Thành viên 2 và 3 |
| Phát hiện | `finding_id`, `scan_id`, URL, `rule_id`, mức độ, bằng chứng và cách khắc phục | Thành viên 4 và 3 |
| Cảnh báo | `alert_id`, `finding_id`, thời điểm, mức độ, trạng thái và lịch sử thao tác | Thành viên 3 |
| Báo cáo | Thời điểm, mục tiêu, URL, quy tắc, mức độ, bằng chứng, cách khắc phục và trạng thái cảnh báo nếu có | Thành viên 5 |

Lưu thời gian theo UTC, hiển thị giờ Việt Nam trên dashboard. Một phát hiện đạt ngưỡng tạo tối đa một cảnh báo trong lượt quét. Trạng thái cảnh báo đi từ **Mới → Đã xem → Đã xử lý**.

## Tiêu chí nghiệm thu chính

- **Tuần 2.** Dashboard lọc được dữ liệu mẫu. Bộ quét thu được phản hồi từ web demo. Bộ quy tắc phân biệt được trang có cấu hình mẫu và trang cố ý thiếu cấu hình.
- **Tuần 3.** Quét trang thiếu cấu hình tạo phát hiện có URL và bằng chứng. Phát hiện đạt ngưỡng sinh cảnh báo trên dashboard. Trang sạch trong bộ demo cho số phát hiện kỳ vọng bằng 0.
- **Tuần 4.** Worker tiếp tục xử lý lượt quét khi tắt Streamlit. Sau khi mở lại, xem được kết quả, xử lý cảnh báo và xuất báo cáo.
- **Tuần 5–6.** Kiểm tra mục tiêu ngoài phạm vi, timeout và việc lưu lặp. Chạy lại ca demo từ bản cài mới theo README.

## Hướng dẫn từng thành viên

- [Thành viên 1 — Dashboard và điều phối nhóm](docs/huong-dan/THANH_VIEN_01.md)
- [Thành viên 2 — Thu thập phản hồi HTTP và tiến trình quét](docs/huong-dan/THANH_VIEN_02.md)
- [Thành viên 3 — Lưu dữ liệu và quản lý vòng đời cảnh báo](docs/huong-dan/THANH_VIEN_03.md)
- [Thành viên 4 — Phát hiện và phân mức độ từ phản hồi HTTP](docs/huong-dan/THANH_VIEN_04.md)
- [Thành viên 5 — Môi trường thử nghiệm, xuất báo cáo và bàn giao](docs/huong-dan/THANH_VIEN_05.md)
