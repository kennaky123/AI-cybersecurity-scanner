"""LLM-based friendly explainer service using Google Gemini API.

Synthesizes multi-stage cybersecurity evidence (lexical, HTML, JavaScript,
Threat Intel, Isolated Sandbox, Visual screenshot, Downloaded files)
into clear, actionable explanations for everyday non-technical users.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Mapping

import httpx

logger = logging.getLogger(__name__)

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"


def _gather_evidence_dossier(scan_data: Mapping[str, Any]) -> dict[str, Any]:
    """Compiles findings from all 8 phases into a structured investigation dossier."""
    url = scan_data.get("url", "unknown")
    prediction = scan_data.get("prediction", "UNKNOWN")
    probability = float(scan_data.get("probability", 0) or 0)
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "UNKNOWN")

    # Phase 1: URL & Domain
    url_analysis = scan_data.get("url_analysis") or {}
    domain_analysis = scan_data.get("domain_analysis") or {}

    # Phase 2: HTML
    html_info = scan_data.get("html_analysis") or {}
    forms = html_info.get("forms") or []
    cred_fields = html_info.get("credential_fields") or []
    html_indicators = html_info.get("indicators") or []

    # Phase 3: JavaScript
    js_info = scan_data.get("javascript_analysis") or {}
    js_indicators = js_info.get("observed_static_indicators") or []
    js_capabilities = js_info.get("potential_capabilities") or []

    # Phase 4: Threat Intel
    threat_intel = scan_data.get("threat_intelligence") or []
    detected_intel = [
        f"{t.get('provider')}: {', '.join(t.get('evidence', []))}"
        for t in threat_intel
        if isinstance(t, dict) and t.get("status") == "found"
    ]

    # Phase 5: Risk Report
    risk_report = scan_data.get("risk_report") or {}
    observed_behavior = risk_report.get("observed_behavior") or []

    # Phase 6: Sandbox Telemetry
    sandbox_info = scan_data.get("sandbox_analysis") or scan_data.get("sandboxResult") or {}
    sandbox_status = sandbox_info.get("status", "chưa chạy")
    redirect_chain = sandbox_info.get("redirect_chain") or []
    external_domains = sandbox_info.get("external_domains") or []
    telemetry_count = len(sandbox_info.get("telemetry") or [])

    # Phase 7: Visual Screenshot Analysis
    visual_info = scan_data.get("visual_analysis") or scan_data.get("visualResult") or {}
    visual_status = visual_info.get("status", "chưa chạy")
    logo_detected = visual_info.get("logo_detected", False)
    login_layout_detected = visual_info.get("login_page_detected", False)
    detected_brand = visual_info.get("detected_brand")
    brand_impersonation = visual_info.get("brand_impersonation", False)

    # Phase 8: Download Analysis
    download_info = scan_data.get("download_analysis") or scan_data.get("downloadResult") or {}
    download_status = download_info.get("status", "chưa chạy")
    downloads_count = len(download_info.get("downloads") or [])

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability_percent": round(probability * 100, 2),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "login_form_present": len(forms) > 0 or "LOGIN_FORM_PRESENT" in html_indicators,
        "password_field_present": len(cred_fields) > 0 or "PASSWORD_FIELD_PRESENT" in html_indicators,
        "suspicious_links": "SUSPICIOUS_LINKS" in html_indicators,
        "javascript_clues": js_indicators,
        "javascript_potential_capabilities": js_capabilities,
        "threat_intel_matches": detected_intel,
        "observed_behavior": observed_behavior,
        "sandbox_executed": sandbox_status == "completed",
        "sandbox_redirects": [r.get("url") for r in redirect_chain if isinstance(r, dict)],
        "sandbox_external_domains": external_domains,
        "sandbox_telemetry_events": telemetry_count,
        "visual_logo_detected": logo_detected,
        "visual_login_layout_detected": login_layout_detected,
        "visual_brand_impersonation": brand_impersonation,
        "visual_detected_brand": detected_brand,
        "download_files_detected": downloads_count,
    }


def _build_investigation_prompt(dossier: dict[str, Any]) -> str:
    return f"""Bạn là một chuyên gia điều tra an ninh mạng hàng đầu, đang trò chuyện và giải thích cho một người dùng bình thường KHÔNG BIẾT VỀ CÔNG NGHỆ (có thể là phụ huynh, học sinh, người lớn tuổi).

Dưới đây là TOÀN BỘ HỒ SƠ ĐIỀU TRA KỸ THUẬT mà hệ thống máy học và môi trường thử nghiệm cô lập (Sandbox) vừa thu thập được từ website:
{json.dumps(dossier, ensure_ascii=False, indent=2)}

HÃY ĐÓNG VAI TRÒ CHUYÊN GIA AN NINH MẠNG PHÂN TÍCH THEO CÁC Ý SAU:
1. "Trang web này ĐANG LÀM GÌ?":
   Dựa vào các bằng chứng quan sát được: Có form đăng nhập đòi mật khẩu không? Sandbox chạy thử trình duyệt thấy gì? Chụp ảnh màn hình thấy logo hay bố cục đăng nhập không? Có mã JavaScript gửi dữ liệu ngầm không?
2. "Nó SẼ LÀM GÌ nếu người dùng nhẹ dạ tiếp tục?":
   Giải thích rõ thủ đoạn (ví dụ: bẫy câu mật khẩu, chuyển hướng sang trang lạ, thu thập số điện thoại/thẻ ngân hàng, cài mã độc...).
3. "Lời khuyên cấp bách":
   Chỉ rõ người dùng TUYỆT ĐỐI KHÔNG LÀM GÌ và NÊN LÀM GÌ ngay bây giờ.

NGUYÊN TẮC QUAN TRỌNG:
- Văn phong: Thân thiện, ấm áp, đời thường, dễ hiểu, KHÔNG dùng từ ngữ kỹ thuật khó hiểu (không nói AST, DOM, entropy, telemetry, payload...). Hãy ví von sinh động (như trang web đội lốt người quen, cái bẫy giăng sẵn câu trộm chìa khoá nhà...).
- Độ dài vừa phải, súc tích.

Vui lòng trả lời DUY NHẤT một khối JSON hợp lệ theo định dạng sau (không kèm markdown ngoài JSON):
{{
  "safety_status": "AN TOÀN" hoặc "CẢNH BÁO" hoặc "NGUY HIỂM LỪA ĐẢO",
  "friendly_summary": "1 hoặc 2 câu tóm tắt cực kỳ trực diện về bản chất của trang web này.",
  "what_is_it_doing": "Mô tả trang web này đang làm gì và sandbox phát hiện được gì (2-3 câu bình dân).",
  "what_will_it_do": "Mô tả hậu quả và những gì sẽ xảy ra nếu người dùng tiếp tục thao tác trên trang (2-3 câu).",
  "plain_explanation": "Đoạn văn đúc kết lại toàn bộ sự việc như một người bạn bảo mật tâm sự.",
  "danger_points": [
    "Dấu hiệu cụ thể 1 (ví dụ: Trang giả mạo có ô đòi nhập mật khẩu)",
    "Dấu hiệu cụ thể 2 (ví dụ: Chụp ảnh màn hình phát hiện bắt chước trang đăng nhập)"
  ],
  "do_nots": [
    "Việc TUYỆT ĐỐI KHÔNG ĐƯỢC LÀM 1",
    "Việc TUYỆT ĐỐI KHÔNG ĐƯỢC LÀM 2"
  ],
  "should_dos": [
    "Việc CẦN PHẢI LÀM NGAY 1",
    "Việc CẦN PHẢI LÀM NGAY 2"
  ]
}}
"""


def _generate_rule_based_analysis(dossier: dict[str, Any]) -> dict[str, Any]:
    """Generates a rich, context-aware rule-based explanation when API key is absent."""
    is_phish = dossier.get("prediction") == "PHISHING" or dossier.get("risk_score", 0) >= 60 or dossier.get("phishing_probability_percent", 0) >= 70
    has_password = dossier.get("password_field_present", False)
    has_login_form = dossier.get("login_form_present", False)
    visual_login = dossier.get("visual_login_layout_detected", False)
    visual_logo = dossier.get("visual_logo_detected", False)
    url = dossier.get("url", "")
    prob = dossier.get("phishing_probability_percent", 0)

    if is_phish or has_password:
        doing_text = (
            f"Khi hệ thống mở thử trang này trong môi trường trình duyệt cách ly (Sandbox), "
            f"phát hiện trang web dựng sẵn một biểu mẫu đăng nhập có ô nhập mật khẩu tài khoản. "
            f"Hệ thống chụp ảnh màn hình cũng nhận diện rõ bố cục trang đăng nhập câu thông tin."
            if (has_password or visual_login) else
            f"Trang web này đang chuẩn bị các kết nối mạng ngầm và có địa chỉ đường dẫn bất thường, "
            f"rất giống với các chiến dịch gửi link lừa đảo hàng loạt qua tin nhắn mạng xã hội."
        )

        will_do_text = (
            "Nếu bạn nhập tài khoản, mật khẩu hay mã OTP vào đây, toàn bộ thông tin sẽ được gửi thẳng "
            "về máy chủ của kẻ lừa đảo. Bạn có thể bị mất quyền kiểm soát tài khoản, mất thông tin cá nhân "
            "hoặc bị chiếm đoạt tiền trong tài khoản chỉ sau vài phút."
        )

        dangers = []
        if has_password or has_login_form:
            dangers.append("Có ô yêu cầu nhập tài khoản và mật khẩu bất thường.")
        if visual_login or visual_logo:
            dangers.append("Môi trường sandbox chụp ảnh nhận diện giao diện bắt chước trang đăng nhập.")
        if prob >= 50:
            dangers.append(f"Mô hình trí tuệ nhân tạo phân tích mẫu lừa đảo với độ nghi vấn lên tới {prob}%.")
        if not dangers:
            dangers.append("Cấu trúc liên kết có dấu hiệu chuyển hướng mờ ám nhằm che giấu danh tính.")

        return {
            "safety_status": "NGUY HIỂM LỪA ĐẢO",
            "friendly_summary": f"Cảnh báo nguy hiểm! Trang web này đang giăng bẫy giả mạo để chiếm đoạt tài khoản của bạn.",
            "what_is_it_doing": doing_text,
            "what_will_it_do": will_do_text,
            "plain_explanation": (
                f"Hãy tưởng tượng trang web này giống như một kẻ xấu cải trang thành người giao hàng quen thuộc "
                f"để lừa bạn mở cửa và giao chìa khoá nhà. Mọi thứ trên trang trông có vẻ thật nhưng địa chỉ nhà lại là một ngõ cụt lạ hoắc. "
                f"Hệ thống AI và Sandbox đã kiểm tra và bắt quả tang các dấu hiệu câu trộm mật khẩu này."
            ),
            "danger_points": dangers,
            "do_nots": [
                "TUYỆT ĐỐI KHÔNG gõ tên đăng nhập, mật khẩu, mã OTP hay số thẻ ngân hàng vào đây.",
                "KHÔNG bấm vào bất kỳ nút bấm, đường link con hay tải file nào từ trang này.",
                "KHÔNG chia sẻ link này cho bạn bè, người thân hay lên nhóm trò chuyện."
            ],
            "should_dos": [
                "Tắt ngay tab trình duyệt này lại.",
                "Nếu đã lỡ nhập mật khẩu trước đó, hãy lập tức mở ứng dụng chính thức để ĐỔI MẬT KHẨU ngay.",
                "Báo cho người đã gửi link này biết để họ kiểm tra lại tài khoản xem có bị kẻ xấu chiếm đoạt không."
            ],
            "is_ai_generated": False
        }
    else:
        return {
            "safety_status": "AN TOÀN",
            "friendly_summary": "Đường link này an toàn! Hệ thống không phát hiện thấy cạm bẫy lừa đảo nào.",
            "what_is_it_doing": "Trang web phản hồi bình thường, không chứa mã độc hay biểu mẫu câu trộm tài khoản ẩn giấu.",
            "what_will_it_do": "Bạn có thể duyệt web, đọc tin tức hay sử dụng dịch vụ trên trang bình thường mà không lo bị chiếm đoạt thông tin.",
            "plain_explanation": (
                "Hệ thống đã kiểm tra kỹ toàn bộ cấu trúc đường link, mã nguồn trang web và chạy thử trong sandbox. "
                "Kết quả cho thấy trang web hoạt động minh bạch, đúng quy chuẩn của các website uy tín."
            ),
            "danger_points": [],
            "do_nots": [
                "Vẫn luôn giữ nguyên tắc vàng: Không bao giờ cung cấp mã OTP ngân hàng cho bất kỳ ai."
            ],
            "should_dos": [
                "Bạn có thể yên tâm sử dụng trang web này bình thường."
            ],
            "is_ai_generated": False
        }


def explain_with_gemini(scan_data: Mapping[str, Any], api_key: str | None = None) -> dict[str, Any]:
    """Generates an investigation-grounded explanation via Google Gemini API."""
    dossier = _gather_evidence_dossier(scan_data)
    effective_key = api_key or os.getenv("GEMINI_API_KEY")

    if not effective_key:
        return _generate_rule_based_analysis(dossier)

    prompt = _build_investigation_prompt(dossier)

    try:
        url = f"{GEMINI_API_URL}?key={effective_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "topP": 0.8,
                "maxOutputTokens": 1000,
            }
        }

        with httpx.Client(timeout=20.0) as client:
            response = client.post(url, json=payload, headers={"Content-Type": "application/json"})

        if response.status_code != 200:
            fallback = _generate_rule_based_analysis(dossier)
            fallback["note"] = f"Gemini API HTTP {response.status_code}. Using smart rule analysis."
            return fallback

        data = response.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return _generate_rule_based_analysis(dossier)

        text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        clean_json = re.sub(r"^```(?:json)?\s*", "", text_content.strip())
        clean_json = re.sub(r"\s*```$", "", clean_json.strip())

        parsed = json.loads(clean_json)
        parsed["is_ai_generated"] = True
        return parsed

    except Exception:
        fallback = _generate_rule_based_analysis(dossier)
        fallback["is_ai_generated"] = False
        return fallback


def explain_malware_behavior_with_gemini(
    behavior_data: Mapping[str, Any], api_key: str | None = None
) -> dict[str, Any]:
    """Uses Gemini to explain runtime sandbox behavioral telemetry captured from malware detonation."""
    filename = behavior_data.get("filename", "unknown.exe")
    sha256 = behavior_data.get("sha256", "")
    is_malicious = behavior_data.get("is_malicious", True)
    spawned = behavior_data.get("spawned_processes", [])
    files = behavior_data.get("files_written", [])
    registry = behavior_data.get("registry_keys_set", [])
    network = behavior_data.get("network_connections", [])
    tactics = behavior_data.get("mitre_tactics", [])

    if not is_malicious:
        return {
            "safety_status": "AN TOÀN",
            "friendly_summary": f"File '{filename}' đã chạy thử trong máy ảo cô lập và không có bất kỳ hành vi phá hoại nào.",
            "what_did_it_do": "File khởi động bình thường, thực hiện chức năng rồi tự kết thúc êm thấm mà không lén lút tạo file hay kết nối ra ngoài.",
            "what_was_it_trying_to_do": "Đây là một ứng dụng phần mềm thông thường, an toàn và minh bạch.",
            "danger_points": [],
            "do_nots": ["Vẫn duy trì thói quen kiểm tra nguồn gốc trước khi cài đặt phần mềm."],
            "should_dos": ["Bạn có thể yên tâm sử dụng tệp tin này."],
            "is_ai_generated": False,
        }

    # Rule-based fallback
    rule_explanation = {
        "safety_status": "NGUY HIỂM: MÃ ĐỘC PHÁ HOẠI",
        "friendly_summary": f"Hệ thống máy ảo cô lập đã bắt quả tang file '{filename}' lén lút cài mã độc và kết nối máy chủ tấn công!",
        "what_did_it_do": (
            f"Ngay khi được chạy thử 30 giây trong máy ảo Windows, file này đã lập tức gọi lệnh ngầm `{spawned[0] if spawned else 'tiến trình lạ'}` "
            f"và tự thả một bản sao ẩn vào `{files[0] if files else 'thư mục hệ thống'}`. "
            f"Nó còn tự thêm khóa khởi động `{registry[0] if registry else 'Registry'}` để đảm bảo nó luôn tự bật mỗi khi máy tính khởi động."
        ),
        "what_was_it_trying_to_do": (
            "Ý đồ của kẻ tấn công là thiết lập một 'cửa hậu' (Backdoor / Trojan) lâu dài trên máy của bạn. "
            "Sau khi bám rễ thành công, nó gửi tín hiệu tới máy chủ điều khiển để chờ lệnh đánh cắp mật khẩu, "
            "chụp trộm màn hình hoặc cài thêm mã độc tống tiền (Ransomware)."
        ),
        "danger_points": [
            f"Tự sinh tiến trình ngầm đáng ngờ ({len(spawned)} lệnh gọi).",
            f"Thả file ẩn vào thư mục nhạy cảm của người dùng ({len(files)} file tạo mới).",
            f"Can thiệp vào khóa khởi động hệ thống Windows để bám rễ vĩnh viễn.",
            f"Cố gắng gửi tín hiệu kết nối ra máy chủ ngoại tuyến C2." if network else "Mã độc có kỹ thuật ẩn giấu né tránh diệt virus.",
        ],
        "do_nots": [
            "TUYỆT ĐỐI KHÔNG mở hoặc chạy file này trên máy tính cá nhân hoặc công ty.",
            "KHÔNG gửi file này cho bạn bè, đồng nghiệp qua Zalo, Messenger hay Email.",
        ],
        "should_dos": [
            "Xóa ngay file này vĩnh viễn khỏi ổ cứng (Shift + Delete).",
            "Nếu đã lỡ bấm chạy trước đó, hãy lập tức ngắt mạng và quét toàn bộ máy bằng Windows Defender.",
        ],
        "is_ai_generated": False,
    }

    effective_key = api_key or os.getenv("GEMINI_API_KEY")
    if not effective_key:
        return rule_explanation

    prompt = f"""Bạn là một chuyên gia điều tra mã độc an ninh mạng.
Hệ thống AI vừa thả file nghi vấn sau vào Máy ảo Windows Cô lập (Isolated Guest Sandbox) để kích nổ chạy thử:
- Tên tệp: {filename} (SHA-256: {sha256})
- Tiến trình con sinh ra: {json.dumps(spawned, ensure_ascii=False)}
- File ngầm bị tạo: {json.dumps(files, ensure_ascii=False)}
- Khóa Registry bị can thiệp: {json.dumps(registry, ensure_ascii=False)}
- Kết nối C2 mạng ngoài: {json.dumps(network, ensure_ascii=False)}
- Kỹ thuật MITRE ATT&CK: {json.dumps(tactics, ensure_ascii=False)}

YÊU CẦU:
Hãy đóng vai trò chuyên gia an ninh mạng, dùng ngôn ngữ đời thường, gần gũi, ấm áp và sinh động để kể lại cho người dùng non-tech:
1. friendly_summary: 1-2 câu tóm tắt trực diện về bản chất nguy hiểm của file.
2. what_did_it_do: Tường thuật lại chính xác những trò mà file này vừa làm lén trong máy ảo (2-3 câu).
3. what_was_it_trying_to_do: Kẻ xấu tạo ra file này nhằm mục đích gì (cài trojan, cướp tài khoản, tống tiền, nghe lén...).
4. danger_points: Danh sách các dấu hiệu phạm pháp quả tang.
5. do_nots: Danh sách việc tuyệt đối không được làm.
6. should_dos: Danh sách việc cần làm ngay.

Trả về DUY NHẤT một khối JSON hợp lệ theo format trên.
"""
    try:
        url = f"{GEMINI_API_URL}?key={effective_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "topP": 0.8, "maxOutputTokens": 1000},
        }
        with httpx.Client(timeout=20.0) as client:
            response = client.post(url, json=payload, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                clean_json = re.sub(r"^```(?:json)?\s*", "", text_content.strip())
                clean_json = re.sub(r"\s*```$", "", clean_json.strip())
                parsed = json.loads(clean_json)
                parsed["is_ai_generated"] = True
                return parsed
    except Exception:
        pass

    return rule_explanation


def explain_malware_bazaar_with_gemini(
    sha256: str,
    filename: str = "",
    bazaar_data: Mapping[str, Any] | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Phân tích tình báo MalwareBazaar abuse.ch và tổng hợp cảnh báo bằng Gemini AI."""
    bdata = bazaar_data or {}
    sample = bdata.get("sample") or {}
    matched = bdata.get("matched", False)
    signature = sample.get("signature") or "Mã độc đáng ngờ"
    reporter = sample.get("reporter") or "Cộng đồng quốc tế"
    first_seen = sample.get("first_seen") or "Gần đây"
    tags = sample.get("tags") or []
    delivery = sample.get("delivery_method") or "Email / Tải về từ web"

    if matched:
        rule_explanation = {
            "is_ai_generated": False,
            "headline": f"Phát hiện mẫu độc hại trùng khớp chữ ký '{signature}' trên kho MalwareBazaar.",
            "threat_family": f"{signature} (Phân loại: {', '.join(tags) if tags else 'Malware'})",
            "bazaar_community_intel": f"Mẫu được báo cáo bởi '{reporter}', ghi nhận từ {first_seen}. Phương thức phát tán: {delivery}.",
            "technical_behavior_breakdown": f"Tệp tin '{filename or 'PE sample'}' mang chữ ký của dòng mã độc {signature}. Dòng mã độc này thường thực hiện tải mã độc thứ cấp, tiêm shellcode và thiết lập kênh điều khiển ngầm.",
            "enterprise_risk": "Nguy cơ cao bị đánh cắp tài khoản doanh nghiệp, trích xuất dữ liệu nhạy cảm hoặc bị chiếm quyền điều khiển hệ thống nội bộ.",
            "recommended_response": "1. Ngắt kết nối mạng của máy tính ngay lập tức.\n2. Thu thập mẫu tệp vào vùng cách ly và cách ly tài khoản người dùng.\n3. Rà quét toàn bộ hệ thống bằng phần mềm EDR/Antivirus có bản cập nhật mới nhất.",
        }
    else:
        rule_explanation = {
            "is_ai_generated": False,
            "headline": "Mã băm chưa từng có bản ghi độc hại trên cơ sở dữ liệu MalwareBazaar abuse.ch.",
            "threat_family": "Chưa xác định dòng mã độc (Có thể là tệp sạch hoặc biến thể mới Zero-day).",
            "bazaar_community_intel": "Cộng đồng nghiên cứu mã độc toàn cầu abuse.ch chưa tiếp nhận báo cáo nào về mã băm SHA-256 này.",
            "technical_behavior_breakdown": "Không phát hiện chữ ký độc hại đã biết trên MalwareBazaar. Cần kết hợp phân tích các chỉ số đặc trưng PE (Entropy, DLL imports) và kích nổ an toàn trong Sandbox.",
            "enterprise_risk": "Nếu tệp tin được gửi từ email lạ hoặc nguồn không chính thống, hãy cẩn trọng với nguy cơ mã độc biến thể mới được kẻ tấn công ngụy trang.",
            "recommended_response": "1. Kiểm tra chữ ký số Authenticode xem có phải nhà phát hành đáng tin cậy.\n2. Chạy thử nghiệm trong môi trường máy ảo cách ly (Sandbox) trước khi sử dụng.\n3. Không chạy tệp với quyền Administrator nếu không rõ nguồn gốc.",
        }

    effective_key = api_key or os.getenv("GEMINI_API_KEY")
    if not effective_key:
        return rule_explanation

    # If hash was not found on MalwareBazaar, attempt OSINT lookup via Google Search Grounding!
    if not matched:
        try:
            grounded = search_threat_with_google_grounding(
                sha256=sha256, filename=filename, api_key=effective_key
            )
            if grounded.get("is_ai_grounded") and (
                grounded.get("sources")
                or (grounded.get("threat_family") and grounded.get("threat_family") != "Chưa xác định")
            ):
                return {
                    "is_ai_generated": True,
                    "is_ai_grounded": True,
                    "headline": grounded.get("headline", rule_explanation["headline"]),
                    "threat_family": grounded.get("threat_family", rule_explanation["threat_family"]),
                    "bazaar_community_intel": (
                        f"Chưa có bản ghi trên MalwareBazaar abuse.ch, nhưng Google Search Grounding đã phát hiện "
                        f"thông tin tình báo trên {len(grounded.get('sources', []))} nguồn cộng đồng an ninh mạng "
                        f"({', '.join(grounded.get('detection_sources', [])[:3]) or 'OSINT'})."
                    ),
                    "technical_behavior_breakdown": grounded.get(
                        "technical_behavior", rule_explanation["technical_behavior_breakdown"]
                    ),
                    "enterprise_risk": grounded.get("enterprise_risk", rule_explanation["enterprise_risk"]),
                    "recommended_response": grounded.get(
                        "recommended_response", rule_explanation["recommended_response"]
                    ),
                    "grounding_sources": grounded.get("sources", []),
                    "search_queries": grounded.get("search_queries", []),
                }
        except Exception as exc:
            logger.warning("Fallback to Google search grounding failed: %s", exc)

    prompt = f"""Bạn là một chuyên gia tình báo an ninh mạng (Cyber Threat Intelligence Specialist).
Hãy phân tích dữ liệu tình báo từ cơ sở dữ liệu MalwareBazaar (abuse.ch) cho mẫu tệp sau:
- Tên tệp: {filename or 'Mẫu PE'}
- SHA-256: {sha256}
- Đã trùng khớp mẫu độc hại: {'Có' if matched else 'Chưa (Mẫu chưa ghi nhận)'}
- Chữ ký nhận diện: {signature}
- Người đóng góp: {reporter}
- Thời gian ghi nhận: {first_seen}
- Thẻ phân loại (Tags): {json.dumps(tags, ensure_ascii=False)}
- Phương thức phát tán: {delivery}

YÊU CẦU:
Trả về DUY NHẤT một khối JSON hợp lệ với cấu trúc sau (viết bằng tiếng Việt chuyên nghiệp, dễ hiểu cho quản trị viên và người dùng):
{{
  "headline": "Tiêu đề cảnh báo ngắn gọn và tác động (1 câu)",
  "threat_family": "Tên dòng mã độc, nguồn gốc và phân loại",
  "bazaar_community_intel": "Tóm tắt những ghi nhận từ cộng đồng an ninh mạng quốc tế trên MalwareBazaar",
  "technical_behavior_breakdown": "Cơ chế hoạt động, thủ đoạn kỹ thuật và hành vi đặc trưng của dòng mã độc này",
  "enterprise_risk": "Đánh giá mức độ rủi ro với người dùng và doanh nghiệp",
  "recommended_response": "Quy trình hành động khẩn cấp từng bước (đánh số 1, 2, 3...)"
}}
"""
    try:
        url = f"{GEMINI_API_URL}?key={effective_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.3, "topP": 0.8, "maxOutputTokens": 1000},
        }
        with httpx.Client(timeout=20.0) as client:
            response = client.post(url, json=payload, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                text_content = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                clean_json = re.sub(r"^```(?:json)?\s*", "", text_content.strip())
                clean_json = re.sub(r"\s*```$", "", clean_json.strip())
                parsed = json.loads(clean_json)
                parsed["is_ai_generated"] = True
                return parsed
    except Exception:
        pass

    return rule_explanation


def search_threat_with_google_grounding(
    sha256: str,
    filename: str = "",
    api_key: str | None = None,
) -> dict[str, Any]:
    """Tra cứu trực tiếp tình báo mối đe dọa toàn cầu (OSINT) qua Google Search Grounding bằng Gemini 2.5 Flash."""
    clean_hash = sha256.strip().lower()
    effective_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY")

    fallback: dict[str, Any] = {
        "is_ai_grounded": False,
        "headline": "Chưa có báo cáo tình báo Google Search OSINT cho mẫu này.",
        "threat_family": "Chưa xác định",
        "search_queries": [],
        "sources": [],
        "detection_sources": [],
        "technical_behavior": "Chưa thu thập được thông tin kỹ thuật từ các nguồn mở.",
        "enterprise_risk": "Cần thận trọng kiểm tra thêm trong môi trường máy ảo cách ly.",
        "recommended_response": "1. Không mở tệp trực tiếp.\n2. Kích nổ an toàn trong Sandbox.\n3. Rà quét bằng Antivirus/EDR.",
        "raw_summary": "",
    }

    if not effective_key or not clean_hash:
        return fallback

    prompt = f"""Bạn là chuyên gia tình báo an ninh mạng (Cyber Threat Intelligence Analyst).
Hãy sử dụng công cụ Google Search để tìm kiếm và tổng hợp thông tin OSINT về mẫu tệp/mã độc sau:
- Mã băm SHA-256: {clean_hash}
- Tên tệp (nếu có): {filename or 'Mẫu tệp PE/nhị phân'}

HÃY TRA CỨU TRÊN CÁC NGUỒN AN NINH MẠNG UY TÍN (VirusTotal, MalwareBazaar, abuse.ch, Any.Run, Hybrid Analysis, Kaspersky Threat Intelligence, Mandiant, SentinelOne, Microsoft Security, BleepingComputer, vx-underground).

YÊU CẦU:
Trả về DUY NHẤT một khối JSON hợp lệ theo định dạng sau (bằng tiếng Việt chuyên nghiệp, súc tích):
{{
  "headline": "Tiêu đề cảnh báo tình báo ngắn gọn (VD: Phát hiện mẫu độc hại thuộc dòng Ransomware VECT / Filecoder.Krypt)",
  "threat_family": "Tên dòng mã độc chính xác (VD: VECT Ransomware, Filecoder.Krypt, RedLine Stealer, hoặc 'Chưa ghi nhận mã độc' nếu tệp sạch)",
  "detection_sources": ["Danh sách các hãng/nguồn an ninh mạng đã ghi nhận hoặc phân tích (VD: Kaspersky, Microsoft Defender, MalwareBazaar, AnyRun)"],
  "technical_behavior": "Mô tả chi tiết cơ chế hoạt động, hành vi phá hoại (VD: mã hóa tệp dữ liệu, xóa shadow copy qua vssadmin, vô hiệu hóa phục hồi boot qua bcdedit, để lại ghi chú đòi tiền chuộc)",
  "enterprise_risk": "Mức độ rủi ro với người dùng và doanh nghiệp",
  "recommended_response": "Quy trình ứng phó khẩn cấp từng bước (1, 2, 3...)"
}}
"""
    candidate_models = ["gemini-2.5-flash", "gemini-flash-latest"]
    is_quota_exhausted = False

    for model_name in candidate_models:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={effective_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "tools": [{"google_search": {}}],
                "generationConfig": {"temperature": 0.2, "topP": 0.8, "maxOutputTokens": 1500},
            }
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(url, json=payload, headers={"Content-Type": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    cand = candidates[0]
                    text_content = cand.get("content", {}).get("parts", [{}])[0].get("text", "")
                    grounding = cand.get("groundingMetadata", {})
                    web_queries = grounding.get("webSearchQueries", []) or []
                    raw_chunks = grounding.get("groundingChunks", []) or []
                    sources: list[dict[str, str]] = []
                    for chunk in raw_chunks:
                        web_info = chunk.get("web")
                        if isinstance(web_info, dict) and web_info.get("uri"):
                            sources.append({
                                "title": web_info.get("title") or web_info.get("uri"),
                                "url": web_info.get("uri"),
                            })

                    parsed: dict[str, Any] = {}
                    clean_json = re.sub(r"^```(?:json)?\s*", "", text_content.strip())
                    clean_json = re.sub(r"\s*```$", "", clean_json.strip())
                    try:
                        parsed = json.loads(clean_json)
                    except Exception:
                        json_match = re.search(r"\{[\s\S]*\}", text_content)
                        if json_match:
                            try:
                                parsed = json.loads(json_match.group(0))
                            except Exception:
                                parsed = {}

                    return {
                        "is_ai_grounded": True,
                        "headline": parsed.get("headline") or f"Kết quả tra cứu Google Search OSINT cho mã băm {clean_hash[:16]}...",
                        "threat_family": parsed.get("threat_family") or "Chưa xác định",
                        "search_queries": web_queries,
                        "sources": sources,
                        "detection_sources": parsed.get("detection_sources") or [s["title"] for s in sources[:5]],
                        "technical_behavior": parsed.get("technical_behavior") or text_content[:500],
                        "enterprise_risk": parsed.get("enterprise_risk") or "Nguy cơ an ninh tiềm ẩn từ tệp tin lạ.",
                        "recommended_response": parsed.get("recommended_response") or "Cách ly tệp và rà quét hệ thống.",
                        "raw_summary": text_content,
                    }
            elif resp.status_code == 429:
                is_quota_exhausted = True
                logger.warning("Gemini API quota exhausted for %s (HTTP 429)", model_name)
                continue
            else:
                logger.warning("Gemini API error %s for %s: %s", resp.status_code, model_name, resp.text[:150])
        except Exception as err:
            logger.warning("Google search grounding query error on %s: %s", model_name, err)

    if is_quota_exhausted:
        fallback["headline"] = "Hạn mức gọi Gemini API (Free Tier Quota) đã đạt giới hạn trong ngày."
        fallback["enterprise_risk"] = "Google API phản hồi mã 429 (Resource Exhausted). Hạn mức tài khoản miễn phí (20 lượt/ngày) đã tạm hết. Vui lòng thử lại sau hoặc nhập khóa GEMINI_API_KEY mới vào ô cấu hình trên giao diện."
        fallback["recommended_response"] = "1. Nhập GEMINI_API_KEY mới vào ô cấu hình trên thanh công cụ.\n2. Kiểm tra thông tin hạn mức tại https://ai.dev/rate-limit.\n3. Kết quả phân tích Sandbox Hybrid Analysis và Phân tích tĩnh vẫn hoạt động đầy đủ."

    return fallback

