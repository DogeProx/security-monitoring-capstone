import csv
import json

mock_data = [
    {
        "Thời điểm": "2026-11-09 18:00:00", "Mục tiêu": "localhost:5000",
        "URL": "/vuln-headers", "Quy tắc": "Thiếu CSP", "Mức độ": "High",
        "Bằng chứng": "Response headers missing Content-Security-Policy",
        "Cách khắc phục": "Thêm header Content-Security-Policy", "Trạng thái cảnh báo": "Mới"
    },
    {
        "Thời điểm": "2026-11-09 18:00:01", "Mục tiêu": "localhost:5000",
        "URL": "/vuln-cookie", "Quy tắc": "Cookie thiếu HttpOnly", "Mức độ": "Medium",
        "Bằng chứng": "Set-Cookie: session_id=token456",
        "Cách khắc phục": "Thêm flag HttpOnly vào Set-Cookie", "Trạng thái cảnh báo": "Đã xem"
    }
]

def export_csv(data, filename="report.csv"):
    keys = data[0].keys()
    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

def export_html(data, filename="report.html"):
    html = "<html><body><table border='1'><tr>"
    # Tạo header
    for key in data[0].keys():
        html += f"<th>{key}</th>"
    html += "</tr>"
    # Tạo row
    for row in data:
        html += "<tr>" + "".join(f"<td>{val}</td>" for val in row.values()) + "</tr>"
    html += "</table></body></html>"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == "__main__":
    export_csv(mock_data)
    export_html(mock_data)
