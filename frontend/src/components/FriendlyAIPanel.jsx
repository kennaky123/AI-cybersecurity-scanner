import { useState } from 'react'
import { getFriendlyAIExplanation } from '../services/api.js'

export default function FriendlyAIPanel({ result, onSwitchToAdvanced }) {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('gemini_api_key') || '')
  const [showKeyInput, setShowKeyInput] = useState(false)
  const [customExplanation, setCustomExplanation] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const data = customExplanation || result?.ai_explanation || {
    safety_status: result?.prediction === 'PHISHING' ? 'NGUY HIỂM LỪA ĐẢO' : 'AN TOÀN',
    friendly_summary: result?.prediction === 'PHISHING'
      ? 'Cảnh báo! Đường link này có dấu hiệu lừa đảo rất cao.'
      : 'Đường link này an toàn! Không phát hiện dấu hiệu lừa đảo nguy hiểm.',
    plain_explanation: result?.prediction === 'PHISHING'
      ? 'Trang web có dấu hiệu giả mạo dịch vụ uy tín để đánh cắp mật khẩu hoặc thông tin của bạn.'
      : 'Hệ thống kiểm tra thấy cấu trúc trang bình thường và không có bẫy lừa đảo.',
    danger_points: [],
    do_nots: ['Không vội vàng nhập mật khẩu hay mã OTP.'],
    should_dos: ['Chỉ đăng nhập bằng ứng dụng chính thức.'],
    is_ai_generated: false
  }

  const isDanger = data.safety_status?.includes('NGUY HIỂM') || result?.prediction === 'PHISHING'
  const isWarning = data.safety_status?.includes('CẢNH BÁO') || (!isDanger && (result?.risk_score || 0) >= 30)
  const statusClass = isDanger ? 'danger' : isWarning ? 'warning' : 'safe'

  const statusBadge = isDanger
    ? '🚨 NGUY HIỂM: CÓ DẤU HIỆU LỪA ĐẢO!'
    : isWarning
    ? '⚠️ CẢNH GIÁC: CÓ DẤU HIỆU BẤT THƯỜNG'
    : '🛡️ AN TOÀN: BẠN CÓ THỂ YÊN TÂM'

  async function handleRefreshAI() {
    setLoading(true)
    setError('')
    try {
      if (apiKey.trim()) {
        localStorage.setItem('gemini_api_key', apiKey.trim())
      }
      const response = await getFriendlyAIExplanation(result, apiKey.trim() || null)
      setCustomExplanation(response)
    } catch (err) {
      setError(err.message || 'Không thể kết nối với Gemini AI.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className={`friendly-ai-panel ${statusClass}`}>
      <div className="friendly-header">
        <div className="friendly-title-group">
          <div className="ai-avatar">🤖</div>
          <div>
            <span className={`status-pill ${statusClass}`}>{statusBadge}</span>
            <h2 className="friendly-title">{data.friendly_summary}</h2>
          </div>
        </div>
        <div className="friendly-actions">
          <button
            type="button"
            className="secondary-btn"
            onClick={() => setShowKeyInput(!showKeyInput)}
            title="Cấu hình Google Gemini API Key"
          >
            🔑 {apiKey ? 'Đã cài Gemini Key' : 'Thêm Gemini Key'}
          </button>
          <button
            type="button"
            className="primary-ai-btn"
            onClick={handleRefreshAI}
            disabled={loading}
          >
            {loading ? 'Đang hỏi AI...' : '✨ Hỏi AI phân tích lại'}
          </button>
        </div>
      </div>

      {showKeyInput && (
        <div className="api-key-box">
          <label htmlFor="gemini-key-input">
            <strong>Google Gemini API Key</strong> (Tuỳ chọn: Nếu nhập, AI sẽ phân tích trực tiếp bằng Gemini Flash):
          </label>
          <div className="api-key-row">
            <input
              id="gemini-key-input"
              type="password"
              placeholder="Dán AIzaSy... API key vào đây"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            <button
              type="button"
              onClick={() => {
                localStorage.setItem('gemini_api_key', apiKey.trim())
                setShowKeyInput(false)
                handleRefreshAI()
              }}
            >
              Lưu & Dùng ngay
            </button>
          </div>
          <small>
            Chưa có API key? Bạn có thể lấy miễn phí 100% tại{' '}
            <a href="https://aistudio.google.com/app/apikey" target="_blank" rel="noreferrer">
              Google AI Studio (aistudio.google.com)
            </a>.
          </small>
        </div>
      )}

      {error && <div className="scanner-error" role="alert">{error}</div>}

      <div className="friendly-body">
        <div className="friendly-card explanation-card">
          <h3>💬 Lời giải thích gần gũi từ Trợ lý An ninh mạng</h3>
          <p className="plain-text">{data.plain_explanation}</p>
          {data.is_ai_generated && (
            <span className="ai-badge">✨ Phân tích thông minh bằng Google Gemini AI</span>
          )}
        </div>

        {data.danger_points && data.danger_points.length > 0 && (
          <div className="friendly-card warning-card">
            <h3>⚠️ Những điểm bất thường phát hiện được:</h3>
            <ul className="friendly-list">
              {data.danger_points.map((item, idx) => (
                <li key={idx}><strong>{item}</strong></li>
              ))}
            </ul>
          </div>
        )}

        <div className="friendly-columns">
          <div className="friendly-card do-not-card">
            <h3>🚫 Tuyệt đối KHÔNG làm:</h3>
            <ul className="friendly-list">
              {data.do_nots?.map((item, idx) => (
                <li key={idx}>{item}</li>
              ))}
            </ul>
          </div>

          <div className="friendly-card should-do-card">
            <h3>✅ Việc NÊN làm ngay bây giờ:</h3>
            <ul className="friendly-list">
              {data.should_dos?.map((item, idx) => (
                <li key={idx}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      <div className="friendly-footer">
        <span>Bạn là kỹ sư bảo mật hoặc muốn xem dữ liệu gốc?</span>
        <button type="button" className="text-btn" onClick={onSwitchToAdvanced}>
          Chuyển sang Chế độ Chuyên gia (10 Giai đoạn kỹ thuật) →
        </button>
      </div>
    </section>
  )
}
