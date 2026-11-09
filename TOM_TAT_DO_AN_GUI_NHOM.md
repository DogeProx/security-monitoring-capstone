# Tóm tắt đồ án gửi nhóm

## Đề tài hiện tại

**Automated Web Security Scanner with Dashboard + Alert System**

Thầy gợi ý phương án **3 + 2**, kết hợp bộ quét bảo mật web có dashboard với hệ thống cảnh báo. Nhóm đã cập nhật kế hoạch từ hướng phân tích log và giám sát tệp ban đầu sang quét ứng dụng web.

Kế hoạch hiện hiểu **Alert System nhận phát hiện từ bộ quét web**, tự tạo cảnh báo khi phát hiện đạt ngưỡng và lưu lịch sử xử lý. Nhóm cần đối chiếu với thầy nếu phần Alert System được yêu cầu có thêm một nguồn cảnh báo riêng.

Luồng demo dự kiến gồm **chọn mục tiêu → quét → lưu phát hiện → tạo cảnh báo → xem và xử lý trên dashboard → xuất báo cáo**. Nhóm dùng web thử nghiệm cục bộ. Các quy tắc minh họa kiểm tra header CSP, X-Content-Type-Options và thuộc tính HttpOnly của cookie phiên khi áp dụng. Công nghệ chính gồm Python 3.11+, Streamlit và SQLite.

## Phân công 5 thành viên

| Thành viên | Phụ trách | Đầu ra cần bàn giao |
|---|---|---|
| **1 — Trưởng nhóm** | Điều phối và làm dashboard Streamlit | Trang tổng quan, lịch sử lượt quét, bảng phát hiện và cảnh báo, bộ lọc, giao diện xử lý cảnh báo |
| **2** | Bộ quét web và tiến trình quét | Thu thập phản hồi HTTP trong phạm vi đã cấu hình, xử lý timeout và chuyển hướng, ghi tiến độ và kết quả lượt quét |
| **3** | SQLite và Alert System | Lưu lượt quét, phát hiện và cảnh báo, tự tạo cảnh báo theo ngưỡng, lưu trạng thái và lịch sử thao tác |
| **4** | Quy tắc phát hiện | Kiểm tra cấu hình từ phản hồi HTTP và trả về mã quy tắc, mức độ, bằng chứng và hướng khắc phục |
| **5** | Web demo, báo cáo và kiểm thử tích hợp | Web thử nghiệm có ca cấu hình đúng và ca thiếu cấu hình, báo cáo CSV/HTML, hướng dẫn demo và kết quả kiểm thử |

## Mốc 6 tuần

| Tuần | Mốc bàn giao |
|---|---|
| **1** | Chốt phạm vi, kiến trúc, bố cục dashboard và trường dữ liệu dùng chung. |
| **2** | Dựng dashboard với dữ liệu mẫu. Chuẩn bị bộ thu phản hồi HTTP, quy tắc, SQLite, web thử nghiệm và báo cáo mẫu. |
| **3** | Tích hợp một lượt quét web demo từ đầu đến cuối. Phát hiện đạt ngưỡng phải tự tạo cảnh báo và hiển thị trên dashboard. |
| **4** | Chạy tiến trình quét độc lập với Streamlit, xử lý cảnh báo và xuất báo cáo từ dữ liệu đã lưu. |
| **5** | Kiểm thử, sửa lỗi, hoàn thiện dữ liệu demo và hướng dẫn cho Windows và Linux. |
| **6** | Chạy lại từ bản cài mới, demo và bàn giao mã nguồn, kiểm thử, báo cáo mẫu và README. |

## Phần đã có trên GitHub

- [README giới thiệu đề tài và lệnh chạy](https://github.com/DogeProx/security-monitoring-capstone/blob/main/README.md)
- [Bảng phân công 6 tuần](https://github.com/DogeProx/security-monitoring-capstone/blob/main/PHAN_CONG.md)
- **Tuần 1 của thành viên 1** · [Thiết kế dashboard và sơ đồ tích hợp](https://github.com/DogeProx/security-monitoring-capstone/blob/main/TUAN_1_THIET_KE_DASHBOARD.md)
- **Tuần 2 của thành viên 1** · [Dashboard Streamlit và dữ liệu mẫu](https://github.com/DogeProx/security-monitoring-capstone/tree/main/dashboard)

Dashboard tuần 2 là bản mẫu giao diện, hiển thị **4 lượt quét, 4 phát hiện và 2 cảnh báo mô phỏng**. Đã kiểm thử bộ lọc theo ngày, mục tiêu và mức độ, gồm lượt quét sạch, lượt quét lỗi và trường hợp kết quả trống. [Commit bàn giao tuần 1 và tuần 2](https://github.com/DogeProx/security-monitoring-capstone/commit/5b7fe00e0e0318c00f1646baf1fc4064a40608dd)

## Chạy dashboard mẫu

Từ thư mục gốc của repo, chạy các lệnh sau rồi mở `http://127.0.0.1:8501`.

```text
python -m pip install -r dashboard/requirements.txt
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

## Việc nhóm cần phối hợp tiếp theo

1. **Thành viên 2 và 4** thống nhất cấu trúc phản hồi HTTP và đầu ra của quy tắc.
2. **Thành viên 3** thống nhất cách ghi, đọc và liên kết lượt quét, phát hiện và cảnh báo với các thành viên còn lại.
3. **Thành viên 5** chia sẻ web demo và kết quả kỳ vọng cho trang sạch, trang thiếu cấu hình và ca lỗi kết nối.
4. **Thành viên 1** nối dashboard với dữ liệu thật khi các giao diện tích hợp đã sẵn sàng và điều phối nghiệm thu mốc tuần 3.
