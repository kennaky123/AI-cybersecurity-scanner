# Hướng Dẫn Đồng Bộ Dự Án & Ghi Chú Kỹ Thuật (AGENT_SYNC_NOTES)

Tài liệu này được tạo nhằm giúp các AI Agent hoặc Lập trình viên trên các máy khác khi pull code về có thể hiểu ngay kiến trúc hệ thống, các thay đổi đã thực hiện, nguyên nhân sự cố và quy trình vận hành đồng bộ.

---

## 1. Tổng Quan Kiến Trúc & Các Giai Đoạn Quét Phishing (Phishing Security Pipeline)

Pipeline phân tích an toàn URL/Phishing gồm 10 giai đoạn (Phases):

| Giai đoạn | Tên kỹ thuật | Chức năng & Cơ chế | Trạng thái mặc định trên link YouTube / Website thông thường |
|---|---|---|---|
| **Giai đoạn 1** | URL Static Analysis | Trích xuất đặc trưng URL (chiều dài, entropy, ký tự lạ, số subdomain, IP format...). | ✅ Hoạt động (Trực tuyến/Tĩnh) |
| **Giai đoạn 2** | HTML Analysis | Phân tích cấu trúc HTML, phát hiện form ẩn, iframe, giả mạo login form. | ✅ Hoạt động (Tải HTML tĩnh) |
| **Giai đoạn 3** | JavaScript Analysis | Phân tích AST / mã JS, phát hiện mã độc làm rối (obfuscation), eval, anti-debugging. | ✅ Hoạt động (Tải Script tĩnh) |
| **Giai đoạn 4** | Threat Intelligence | Tra cứu cơ sở dữ liệu tình báo mối đe dọa (VirusTotal, PhishTank, OpenPhish, Google Safe Browsing). | ✅ Hoạt động (Tra cứu API). *Đã sửa lỗi code `ThreatIntelManager` không iterable*. |
| **Giai đoạn 5** | AI ML Risk Scoring | Đưa các đặc trưng vào mô hình Machine Learning (LightGBM/XGBoost) + SHAP Explainability để tính điểm rủi ro. | ✅ Hoạt động |
| **Giai đoạn 6** | Browser Sandbox Analysis | Chạy URL trong môi trường cách ly (Isolated Container/VM Sandbox) để giám sát hành vi runtime, console logs, network calls, redirects. | 🔒 **Chế độ an toàn (Safe by Design)**: Trả về `unavailable`. Hệ thống KHÔNG tự ý mở trình duyệt thật (Chrome/Edge) trên máy host để tránh bị mã độc khai thác lỗ hổng trình duyệt (Drive-by download, zero-day RCE). Cần tích hợp Docker sandbox. |
| **Giai đoạn 7** | Visual Phishing Analysis | So khớp ảnh chụp màn hình (Screenshot) với các thương hiệu lớn (Google, Microsoft, Facebook...) để phát hiện website giả mạo giao diện (Logo spoofing). | 🔒 Phụ thuộc vào Giai đoạn 6: Khi Sandbox an toàn không mở trình duyệt, không có screenshot -> Trả về `unavailable` hợp lệ. |
| **Giai đoạn 8** | Website Download Analysis | Bắt các luồng tải tệp tự động (Drive-by download) và quét mã độc (PE feature extraction). | 🔒 Phụ thuộc vào Giai đoạn 6 hoặc các link trực tiếp tải file. Với YouTube (không tự tải file `.exe`/`.dll`), số tệp là 0 và mức rủi ro là LOW. |
| **Giai đoạn 9** | Comprehensive Risk Aggregation | Tổng hợp điểm rủi ro từ tất cả các giai đoạn trên với trọng số rủi ro đa tầng. | ✅ Hoạt động |
| **Giai đoạn 10** | Enterprise Security Hardening | Kiểm tra cấu hình bảo mật doanh nghiệp (Domain Trust Guard, CSP, HSTS, Rate Limiting, Audit Logging). | ✅ Hoạt động |

---

## 2. Giải Thích Chi Tiết Về Hiện Tượng Ở Link YouTube (Giai đoạn 4, 6, 7, 8)

### ❌ Giai đoạn 4 (Threat Intelligence): LÀ DO CODE LỖI (ĐÃ SỬA)
- **Nguyên nhân:** Lỗi khởi tạo trong file `backend/app/services/threat_intelligence.py`. 
  Cụ thể, `ThreatIntelManager.__init__` gán `self.providers = self.from_environment()`, trong đó `from_environment` trả về chính một đối tượng `ThreatIntelManager` thay vì danh sách `list[ThreatIntelProvider]`. Khi vòng lặp `for provider in self.providers:` chạy, Python quăng lỗi:
  `TypeError: 'ThreatIntelManager' object is not iterable` dẫn đến phản hồi API `500 Internal Server Error`.
- **Cách khắc phục:** Tách `default_providers()` thành staticmethod trả về danh sách provider, đảm bảo `self.providers` luôn luôn là `list[ThreatIntelProvider]`.

### 🛡️ Giai đoạn 6 (Browser Sandbox): KHÔNG PHẢI YOUTUBE CHẶN, MÀ LÀ BẢO VỆ MÁY CHỦ (SAFE BY DESIGN)
- **Nguyên nhân:** Trình quét an ninh được thiết kế theo nguyên tắc phòng vệ cao nhất. Nếu mở một đường link độc hại bằng trình duyệt thật của máy chủ/máy người dùng, mã độc có thể dùng lỗ hổng zero-day trình duyệt để chiếm quyền máy (Drive-by compromise).
- Vì vậy, hệ thống sử dụng `UnavailableSandboxProvider` làm mặc định an toàn:
  > *"No isolated browser/container provider is configured. No browser was launched on the host machine."*
- Đây **không phải lỗi** và cũng **không phải YouTube chặn**.

### 🖼️ Giai đoạn 7 (Visual Analysis): KẾT QUẢ KÉO THEO TỪ GIAI ĐOẠN 6
- **Nguyên nhân:** Để phát hiện giả mạo giao diện (visual spoofing), hệ thống cần bức ảnh chụp màn hình (screenshot) từ Sandbox ở Giai đoạn 6.
- Do Giai đoạn 6 đang ở chế độ an toàn (không mở trình duyệt thật để chụp), hệ thống không có screenshot để so khớp -> Báo cáo trạng thái `unavailable` ("Chưa có dữ liệu chụp màn hình từ sandbox") là hoàn toàn đúng logic và an toàn.

### 📥 Giai đoạn 8 (Download Analysis): KẾT QUẢ TỰ NHIÊN CỦA WEBSITE AN TOÀN
- **Nguyên nhân:** YouTube là nền tảng video stream, không tự động tải tệp tin thực thi (`.exe`, `.scr`, `.bat`) về máy khi bạn truy cập link. Do đó, số lượng file tải xuống = 0 và mức rủi ro trang web = THẤP (LOW). Đây là hành vi hoàn toàn chính xác.

---

## 3. Chạy Dự Án Bằng Docker

Dự án cung cấp cấu hình `docker-compose.yml` hoàn chỉnh:
```powershell
docker compose up -d
```
- **Backend API:** `cybersecurity_backend` chạy trên cổng `8000` (`http://localhost:8000`)
- **Frontend Dashboard:** `cybersecurity_frontend` chạy trên cổng `5173` (`http://localhost:5173`)

### Quản lý container:
```powershell
docker compose ps
docker compose logs -f
docker compose down
```

Hoặc chạy trực tiếp trên máy chủ cục bộ (không qua Docker):
- Backend: `.\backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000`
- Frontend: `npm run dev` trong thư mục `frontend`
