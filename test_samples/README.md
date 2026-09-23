# Hướng Dẫn Thử Nghiệm Kiểm Tra Malware Và Phishing (Test Samples)

Thư mục `test_samples/` cung cấp các tập tin mẫu an toàn và danh sách URL được phân loại sẵn để bạn dễ dàng test tính năng phát hiện Malware và Phishing trên AI Cybersecurity Scanner.

---

## 1. Cấu Trúc Thư Mục Mẫu

```text
test_samples/
├── 01_benign_executables/      # Các tập tin PE (.exe) hợp lệ và an toàn
│   ├── benign_python.exe       # Trình thực thi Python launcher (Dự đoán: BENIGN / LOW RISK)
│   └── benign_notepad.exe      # Trình thực thi Notepad chuẩn Windows (Dự đoán: BENIGN / LOW RISK)
│
├── 02_invalid_pe_files/        # Các tập tin giả mạo / không đúng định dạng PE
│   ├── not_a_pe.exe            # File văn bản đổi đuôi .exe (Kết quả: HTTP 422 - Thiếu MZ Signature)
│   └── fake_mz_corrupt.exe     # File có header MZ nhưng cấu trúc PE bị hỏng (Kết quả: HTTP 422 - Invalid PE)
│
├── 03_oversized_files/         # Tập tin vượt quá giới hạn dung lượng
│   └── oversized_26mb.exe      # File test 26 MB (Kết quả: HTTP 413 - Payload Too Large)
│
└── 04_phishing_urls/           # Danh sách URL mẫu cho Phishing Scanner
    ├── phishing_urls_sample.txt   # Các URL lừa đảo thực tế (PhishTank/OpenPhish feeds)
    └── legitimate_urls_sample.txt # Các URL hợp lệ (Google, Github, Wikipedia,...)
```

---

## 2. Cách Thực Hiện Test

### A. Kiểm tra qua Giao Diện React Dashboard (Web UI)
1. Khởi chạy Backend FastAPI:
   ```powershell
   python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```
2. Khởi chạy Frontend React:
   ```powershell
   cd frontend
   npm run dev
   ```
3. Mở trình duyệt tại `http://localhost:5173`:
   - Truy cập mục **Malware Scanner**: Kéo thả file từ `01_benign_executables/`, `02_invalid_pe_files/`, hoặc `03_oversized_files/` để xem kết quả phân tích tĩnh PE & Shap explanations.
   - Truy cập mục **Phishing Scanner**: Copy các URL trong `04_phishing_urls/` để xem xác suất Phishing và giải thích đặc trưng lexical URL.

### B. Kiểm tra qua API (cURL / PowerShell)

#### Test File PE Hợp Lệ (`benign_python.exe`):
```powershell
curl.exe -X POST http://127.0.0.1:8000/api/malware/analyze `
  -F "file=@test_samples/01_benign_executables/benign_python.exe"
```

#### Test File Định Dạng Lỗi (`not_a_pe.exe`):
```powershell
curl.exe -X POST http://127.0.0.1:8000/api/malware/analyze `
  -F "file=@test_samples/02_invalid_pe_files/not_a_pe.exe"
```

#### Test Phishing URL:
```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/phishing/analyze `
  -ContentType 'application/json' `
  -Body '{"url":"http://192.168.1.100:8080/paypal-login/verify.php"}'
```

