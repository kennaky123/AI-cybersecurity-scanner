export const translations = {
  // Status values
  'unavailable': 'Không khả dụng',
  'completed': 'Hoàn thành',
  'error': 'Lỗi',
  'timeout': 'Hết thời gian',
  'invalid': 'Không hợp lệ',
  'found': 'Phát hiện',
  'not_found': 'Không tìm thấy',
  'SAFE': 'AN TOÀN',
  'PHISHING': 'LỪA ĐẢO',
  'BENIGN': 'LÀNH TÍNH',
  'MALWARE': 'MÃ ĐỘC',
  'LOW': 'THẤP',
  'MEDIUM': 'TRUNG BÌNH',
  'HIGH': 'CAO',
  'CRITICAL': 'NGHIÊM TRỌNG',
  'UNKNOWN': 'CHƯA BIẾT',
  'Blocked': 'Đã chặn',
  'Review': 'Cần xem xét',
  'Yes': 'Có',
  'No': 'Không',
  'Unknown': 'Không rõ',
  'Possible': 'Có thể',
  'Not established': 'Chưa xác định',
  'None': 'Không có',

  // Dashboard section titles
  'Observed Behavior': 'Hành vi quan sát được',
  'Potential Capability': 'Khả năng tiềm ẩn',
  'Threat Intelligence': 'Tình báo mối đe dọa',
  'Model Prediction': 'Dự đoán mô hình',
  'Recommended next steps': 'Các bước tiếp theo được khuyến nghị',
  'Structured evidence': 'Bằng chứng có cấu trúc',
  'Evidence': 'Bằng chứng',
  'Sandbox status': 'Trạng thái sandbox',

  // Metric labels
  'Status': 'Trạng thái',
  'Telemetry': 'Dữ liệu đo từ xa',
  'Downloads': 'Tệp tải xuống',
  'Redirect chain': 'Chuỗi chuyển hướng',
  'External domains': 'Tên miền ngoài',
  'Execution policy': 'Chính sách thực thi',
  'Brand': 'Thương hiệu',
  'Visual similarity': 'Độ tương đồng hình ảnh',
  'Logo detected': 'Phát hiện logo',
  'Login layout': 'Bố cục đăng nhập',
  'Domain matches brand': 'Tên miền khớp thương hiệu',
  'Brand impersonation': 'Mạo danh thương hiệu',
  'Website risk': 'Rủi ro website',
  'Phishing probability': 'Xác suất lừa đảo',
  'Credential Theft': 'Đánh cắp thông tin',
  'Brand Impersonation': 'Mạo danh thương hiệu',
  'Suspicious JavaScript': 'JavaScript đáng ngờ',
  'Suspicious Redirect': 'Chuyển hướng đáng ngờ',
  'Malicious Download': 'Tải xuống độc hại',

  // Phase titles & misc
  'Phase 8: Website Download Analysis': 'Giai đoạn 8: Phân tích tệp tải xuống từ website',
  'Phishing security dashboard': 'Bảng điều khiển bảo mật phishing',
  'Explainable website assessment': 'Đánh giá website có giải thích',
};

export function t(key) {
  if (!key) return key;
  return translations[key] || key;
}

export function translateStatus(status) {
  if (status === null || status === undefined) return 'Không rõ';
  const strStatus = String(status);
  return translations[strStatus] || strStatus;
}

export function translateEvidence(text) {
  if (!text) return text;
  const evidenceTranslations = {
    'None available': 'Không có dữ liệu',
    'No screenshot was produced by the browser sandbox.': 'Không có ảnh chụp từ sandbox trình duyệt.',
    'No isolated browser/container provider is configured.': 'Chưa cấu hình trình duyệt/container cách ly.',
    'No browser was launched on the host machine.': 'Không có trình duyệt nào được khởi chạy trên máy chủ.',
    'No completed sandbox session was available; no download behavior was confirmed.': 'Không có phiên sandbox hoàn thành; không xác nhận hành vi tải xuống.',
    'Visual similarity is supporting evidence only; it is not a phishing verdict by itself.': 'Độ tương đồng hình ảnh chỉ là bằng chứng hỗ trợ; không phải là kết luận phishing.',
    'Brand impersonation requires context from domain, HTML, threat intelligence, or other signals.': 'Mạo danh thương hiệu cần bối cảnh từ tên miền, HTML, tình báo mối đe dọa, hoặc các tín hiệu khác.'
  };
  return evidenceTranslations[text] || text;
}
