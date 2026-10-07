import { useEffect, useState } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getModelMetrics } from '../services/api.js'

const comparisonPhilosophy = [
  ['Bảo vệ thời gian thực', 'Mạnh: giám sát tiến trình, bộ nhớ và mạng', 'Ngoài phạm vi: phân tích tĩnh theo yêu cầu'],
  ['Danh tiếng đám mây', 'Mạng lưới dữ liệu mối đe dọa lớn', 'Ngoại tuyến: không truy cập URL hay tải dữ liệu bên thứ ba'],
  ['Khả năng giải thích', 'Thường tập trung vào kết luận cuối', 'Hiển thị bằng chứng và đóng góp đặc trưng của model (XAI / SHAP)'],
  ['Khả năng tái lập', 'Engine độc quyền, mã nguồn đóng', 'Feature, metadata, hash và pipeline có thể kiểm thử minh bạch'],
  ['Phân tích an toàn trong lớp học', 'Thiết kế cho bảo vệ endpoint thực tế', 'Đọc PE chỉ đọc, file tạm cách ly và tự động dọn dẹp an toàn'],
]

const strengths = [
  ['01', 'Ngoại tuyến theo thiết kế', 'URL được phân tích lexical mà không gửi HTTP request; binary PE không bao giờ được thực thi.'],
  ['02', 'Bằng chứng minh bạch, không chỉ nhãn', 'Mỗi kết quả đều có xác suất, điểm rủi ro, SHA-256, metadata và đóng góp đặc trưng.'],
  ['03', 'ML có thể kiểm toán (Auditable)', 'Artifact được kiểm tra hash SHA-256, schema và metric trên tập dữ liệu kiểm thử độc lập.'],
  ['04', 'Phạm vi triage rõ ràng', 'Đây là công cụ triage tĩnh hỗ trợ chuyên viên SOC và học thuật, không thay thế EDR thời gian thực.'],
]

export default function ModelMetrics() {
  const [metricsData, setMetricsData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('phishing') // 'phishing' | 'malware'

  useEffect(() => {
    getModelMetrics()
      .then((data) => {
        setMetricsData(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message || 'Không thể tải số liệu mô hình.')
        setLoading(false)
      })
  }, [])

  const currentModel = metricsData ? metricsData[activeTab] : null

  // Prepare chart comparison data
  const chartData = currentModel?.comparison?.map((item) => ({
    name: item.algorithm,
    Accuracy: Number((item.accuracy * 100).toFixed(2)),
    Precision: Number((item.precision * 100).toFixed(2)),
    Recall: Number((item.recall * 100).toFixed(2)),
    F1: Number((item.f1 * 100).toFixed(2)),
    ROCAUC: Number((item.roc_auc * 100).toFixed(2)),
  })) || []

  return (
    <section className="metrics-page bento-container">
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">Đánh giá & Kiểm thử Mô hình AI</p>
          <h1>Hiệu năng & So sánh Mô hình</h1>
          <p className="lead">
            Số liệu thực nghiệm kiểm thử trên tập dữ liệu độc lập (Test Set), không qua làm giả hay gán cứng.
          </p>
        </div>
      </div>

      {/* Model Selection Tabs */}
      <div className="mode-toggle-buttons" style={{ marginBottom: '8px' }}>
        <button
          type="button"
          className={`mode-btn ${activeTab === 'phishing' ? 'active' : ''}`}
          onClick={() => setActiveTab('phishing')}
        >
          ⌁ Mô hình Phishing (PhiUSIIL)
        </button>
        <button
          type="button"
          className={`mode-btn ${activeTab === 'malware' ? 'active' : ''}`}
          onClick={() => setActiveTab('malware')}
        >
          ◈ Mô hình Malware PE (BODMAS / EMBER)
        </button>
      </div>

      {loading && <div className="loading-panel">Đang đọc siêu dữ liệu và số liệu đánh giá mô hình…</div>}
      {error && <div className="scanner-error" role="alert">{error}</div>}

      {!loading && currentModel && (
        <>
          {/* Key Metrics Bento KPI Cards */}
          <div className="bento-row">
            <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
              <span className="bento-feature-pill-label">Mô hình tốt nhất</span>
              <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', color: 'var(--color-accent)', display: 'block', marginTop: '6px' }}>
                {currentModel.selected_model}
              </strong>
              <small style={{ color: 'var(--color-muted)', fontSize: '0.75rem', marginTop: '4px', display: 'block' }}>
                Chiến lược: Tối ưu F1 & ROC-AUC
              </small>
            </div>

            <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
              <span className="bento-feature-pill-label">F1-Score (Test Set)</span>
              <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.6rem', color: 'var(--color-safe)', display: 'block', marginTop: '6px' }}>
                {(currentModel.test_metrics.f1 * 100).toFixed(2)}%
              </strong>
              <small style={{ color: 'var(--color-muted)', fontSize: '0.75rem', marginTop: '4px', display: 'block' }}>
                Cân bằng Precision & Recall
              </small>
            </div>

            <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
              <span className="bento-feature-pill-label">Độ chính xác (Accuracy)</span>
              <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.6rem', color: 'var(--color-warning)', display: 'block', marginTop: '6px' }}>
                {(currentModel.test_metrics.accuracy * 100).toFixed(2)}%
              </strong>
              <small style={{ color: 'var(--color-muted)', fontSize: '0.75rem', marginTop: '4px', display: 'block' }}>
                Trên {currentModel.test_samples.toLocaleString()} mẫu test độc lập
              </small>
            </div>

            <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
              <span className="bento-feature-pill-label">ROC-AUC</span>
              <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.6rem', color: '#f472b6', display: 'block', marginTop: '6px' }}>
                {(currentModel.test_metrics.roc_auc * 100).toFixed(2)}%
              </strong>
              <small style={{ color: 'var(--color-muted)', fontSize: '0.75rem', marginTop: '4px', display: 'block' }}>
                Năng lực phân tách 2 lớp
              </small>
            </div>
          </div>

          {/* Algorithm Comparison Chart in Bento Cell */}
          <div className="bento-cell">
            <div className="bento-cell-header">
              <h2 className="bento-cell-title">So sánh 3 thuật toán huấn luyện</h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>
                Random Forest vs XGBoost vs LightGBM (Validation Set)
              </span>
            </div>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData} margin={{ top: 15, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid stroke="rgba(255, 255, 255, 0.05)" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="var(--color-muted)" tick={{ fontSize: 12 }} />
                <YAxis domain={[90, 100]} stroke="var(--color-muted)" tick={{ fontSize: 11 }} />
                <Tooltip
                  formatter={(val) => [`${val}%`]}
                  contentStyle={{ background: '#12141e', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '6px' }}
                />
                <Legend wrapperStyle={{ fontSize: '0.8rem' }} />
                <Bar dataKey="Accuracy" fill="#38bdf8" name="Accuracy (%)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Precision" fill="#34d399" name="Precision (%)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Recall" fill="#fbbf24" name="Recall (%)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="F1" fill="#f472b6" name="F1-Score (%)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Confusion Matrix & Dataset Specifications Bento Row */}
          <div className="bento-row">
            {/* Confusion Matrix Card */}
            <div className="bento-cell bento-col-6">
              <div className="bento-cell-header">
                <h2 className="bento-cell-title">Ma trận nhầm lẫn (Confusion Matrix)</h2>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>Test Set</span>
              </div>
              <p style={{ color: 'var(--color-muted)', fontSize: '0.82rem', marginBottom: '16px' }}>
                Đo lường trên tập kiểm thử (Test Set) không bị rò rỉ dữ liệu.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div style={{ background: 'rgba(52, 211, 153, 0.08)', border: '1px solid rgba(52, 211, 153, 0.25)', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>True Negative (TN)</div>
                  <strong style={{ fontSize: '1.4rem', color: 'var(--color-safe)', display: 'block', margin: '4px 0' }}>
                    {currentModel.confusion_matrix.true_negative.toLocaleString()}
                  </strong>
                  <div style={{ fontSize: '0.72rem', color: 'var(--color-ink-2)' }}>Lành tính dự đoán đúng</div>
                </div>

                <div style={{ background: 'rgba(251, 191, 36, 0.08)', border: '1px solid rgba(251, 191, 36, 0.25)', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>False Positive (FP)</div>
                  <strong style={{ fontSize: '1.4rem', color: 'var(--color-warning)', display: 'block', margin: '4px 0' }}>
                    {currentModel.confusion_matrix.false_positive.toLocaleString()}
                  </strong>
                  <div style={{ fontSize: '0.72rem', color: 'var(--color-ink-2)' }}>Cảnh báo nhầm (Báo động giả)</div>
                </div>

                <div style={{ background: 'rgba(248, 113, 113, 0.08)', border: '1px solid rgba(248, 113, 113, 0.25)', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>False Negative (FN)</div>
                  <strong style={{ fontSize: '1.4rem', color: 'var(--color-danger)', display: 'block', margin: '4px 0' }}>
                    {currentModel.confusion_matrix.false_negative.toLocaleString()}
                  </strong>
                  <div style={{ fontSize: '0.72rem', color: 'var(--color-ink-2)' }}>Bỏ lọt mối đe dọa</div>
                </div>

                <div style={{ background: 'rgba(52, 211, 153, 0.08)', border: '1px solid rgba(52, 211, 153, 0.25)', borderRadius: '6px', padding: '12px', textAlign: 'center' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>True Positive (TP)</div>
                  <strong style={{ fontSize: '1.4rem', color: 'var(--color-safe)', display: 'block', margin: '4px 0' }}>
                    {currentModel.confusion_matrix.true_positive.toLocaleString()}
                  </strong>
                  <div style={{ fontSize: '0.72rem', color: 'var(--color-ink-2)' }}>Đe dọa phát hiện chính xác</div>
                </div>
              </div>
            </div>

            {/* Dataset & Artifact Integrity Specifications */}
            <div className="bento-cell bento-col-6">
              <div className="bento-cell-header">
                <h2 className="bento-cell-title">Đặc tả Tập mẫu & Tính toàn vẹn</h2>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>Audit Trail</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-rule)', paddingBottom: '6px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Tập dữ liệu:</span>
                  <strong style={{ color: 'var(--color-ink)' }}>{currentModel.dataset_name}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-rule)', paddingBottom: '6px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Tổng số mẫu:</span>
                  <span style={{ color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>{currentModel.total_samples.toLocaleString()} mẫu</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-rule)', paddingBottom: '6px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Phân chia (Train / Val / Test):</span>
                  <span style={{ color: 'var(--color-ink)', fontFamily: 'var(--font-mono)' }}>
                    {currentModel.training_samples.toLocaleString()} / {currentModel.validation_samples.toLocaleString()} / {currentModel.test_samples.toLocaleString()} (70/15/15)
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-rule)', paddingBottom: '6px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Số đặc trưng (Features):</span>
                  <span style={{ color: 'var(--color-accent)', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{currentModel.features_count.toLocaleString()} chiều</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--color-rule)', paddingBottom: '6px' }}>
                  <span style={{ color: 'var(--color-muted)' }}>Thời điểm huấn luyện:</span>
                  <span style={{ color: 'var(--color-ink)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    {currentModel.trained_at_utc ? new Date(currentModel.trained_at_utc).toLocaleString('vi-VN') : 'N/A'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', paddingTop: '6px' }}>
                  <span style={{ color: 'var(--color-muted)', fontSize: '0.78rem' }}>Mã băm Model SHA-256 (Fail-closed audit):</span>
                  <code style={{ fontSize: '0.72rem', background: 'var(--color-paper-3)', padding: '6px 8px', borderRadius: '4px', color: 'var(--color-accent)', wordBreak: 'break-all' }}>
                    {currentModel.artifact_sha256?.model || 'N/A'}
                  </code>
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Answer & Philosophy Cards */}
      <div className="bento-cell" style={{ borderLeft: '3px solid var(--color-accent)' }}>
        <span className="bento-feature-pill-label" style={{ color: 'var(--color-accent)', marginBottom: '8px', display: 'block' }}>
          Câu trả lời trọng tâm khi thuyết trình
        </span>
        <p style={{ margin: 0, lineHeight: 1.6, color: 'var(--color-ink-2)' }}>
          “Hệ thống không cạnh tranh với antivirus thương mại về cơ sở dữ liệu chữ ký, giám sát tiến trình thời gian thực hay sandbox hành vi động. Điểm khác biệt cốt lõi là khả năng <strong>triage phân loại tĩnh ngoại tuyến có giải thích (XAI)</strong>: hiển thị bằng chứng cụ thể, xác suất mô hình, điểm rủi ro, mã băm SHA-256 và giới hạn nhận thức; toàn bộ quy trình có thể kiểm thử và tái lập minh bạch.”
        </p>
      </div>

      <div className="bento-row">
        {strengths.map(([number, title, description]) => (
          <div className="bento-cell bento-col-3" key={number} style={{ padding: '16px' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', fontWeight: 700, color: 'var(--color-accent)' }}>{number}</span>
            <h3 style={{ fontSize: '0.95rem', margin: '8px 0 6px', color: 'var(--color-ink)' }}>{title}</h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--color-muted)', margin: 0, lineHeight: 1.5 }}>{description}</p>
          </div>
        ))}
      </div>

      <section className="comparison-card">
        <div className="card-heading">
          <h2 className="bento-cell-title">So sánh năng lực hệ thống</h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>Phạm vi triage chuyên biệt</span>
        </div>
        <div className="comparison-table-wrap">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Năng lực</th>
                <th>Antivirus thương mại</th>
                <th>AI Cybersecurity Scanner</th>
              </tr>
            </thead>
            <tbody>
              {comparisonPhilosophy.map(([capability, antivirus, project]) => (
                <tr key={capability}>
                  <th>{capability}</th>
                  <td>{antivirus}</td>
                  <td>{project}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <div className="limitation-banner">
        <strong>Lưu ý quan trọng:</strong> Điểm rủi ro THẤP chỉ mang ý nghĩa “rủi ro thấp dựa trên các đặc trưng tĩnh đã trích xuất”, không đảm bảo an toàn tuyệt đối trước mã độc thế hệ mới chưa từng xuất hiện. Môi trường thực tế đòi hỏi kiến trúc phòng thủ theo chiều sâu (Defense-in-Depth).
      </div>
    </section>
  )
}
