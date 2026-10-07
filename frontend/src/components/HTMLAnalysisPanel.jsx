function listValue(items, empty = 'None detected') {
  return items.length ? items.join(', ') : empty
}

export default function HTMLAnalysisPanel({ result, loading, error, onAnalyze }) {
  return (
    <section className="result-section html-analysis-panel">
      <div className="explanation-heading">
        <div><h2>Giai đoạn 2: Phân tích HTML và biểu mẫu</h2><p>Chỉ tải HTML. JavaScript không được chạy, biểu mẫu không được gửi và tài nguyên nhúng không được tải.</p></div>
        <button type="button" className="secondary-button" onClick={onAnalyze} disabled={loading}>{loading ? 'Đang tải HTML…' : 'Phân tích HTML'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && (
        <>
          <div className="metric-grid html-metrics">
            <article><span>Điểm HTML</span><strong>{result.html_score}<small>/100</small></strong></article>
            <article><span>Biểu mẫu</span><strong>{result.forms.length}</strong></article>
            <article><span>Trường nhạy cảm</span><strong>{result.credential_fields.length}</strong></article>
          </div>
          <div className="feature-grid">
            <div><span>Dấu hiệu</span><code>{listValue(result.indicators)}</code></div>
            <div><span>Gửi ra ngoài</span><code>{result.external_submissions.length}</code></div>
            <div><span>IFRAME</span><code>{result.iframes.length}</code></div>
            <div><span>Tài nguyên ngoài</span><code>{result.external_resources.length}</code></div>
            <div><span>Loại dữ liệu</span><code>{listValue([...new Set(result.credential_fields.map((field) => field.type))])}</code></div>
            <div><span>Mã HTTP</span><code>{result.http_status ?? 'Chưa biết'}</code></div>
          </div>
          <div className="analysis-explanations"><h3>What the evidence means</h3><ul>{result.explanation.map((item, index) => <li key={index}>{item}</li>)}</ul></div>
        </>
      )}
    </section>
  )
}
