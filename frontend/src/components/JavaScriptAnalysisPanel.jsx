function listValue(items, empty = 'None observed') {
  return items.length ? items.join(', ') : empty
}

export default function JavaScriptAnalysisPanel({ result, loading, error, onAnalyze }) {
  return (
    <section className="result-section javascript-analysis-panel">
      <div className="explanation-heading">
        <div><h2>Giai đoạn 3: Phân tích JavaScript tĩnh</h2><p>Chỉ kiểm tra mã nguồn. JavaScript không được thực thi trên máy này.</p></div>
        <button type="button" className="secondary-button" onClick={onAnalyze} disabled={loading}>{loading ? 'Đang kiểm tra JS…' : 'Phân tích JavaScript'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && (
        <>
          <div className="metric-grid html-metrics">
            <article><span>Điểm JavaScript</span><strong>{result.javascript_score}<small>/100</small></strong></article>
            <article><span>API quan sát được</span><strong>{result.apis.length}</strong></article>
            <article><span>Hành vi đáng ngờ</span><strong>{result.suspicious_behaviors.length}</strong></article>
          </div>
          <div className="feature-grid">
            <div><span>Dấu hiệu tĩnh</span><code>{listValue(result.observed_static_indicators)}</code></div>
            <div><span>Dấu hiệu mạng</span><code>{listValue(result.network_indicators)}</code></div>
            <div><span>Chuyển hướng</span><code>{result.redirects.length}</code></div>
            <div><span>Script ngoài</span><code>{result.external_scripts.length}</code></div>
            <div><span>Làm rối mã</span><code>{result.obfuscation.detected ? 'Có' : 'Không thấy'}</code></div>
            <div><span>Khả năng tiềm ẩn</span><code>{result.potential_capabilities.length}</code></div>
          </div>
          <div className="analysis-explanations"><h3>Observed vs possible</h3><ul>{result.explanation.map((item, index) => <li key={index}>{item}</li>)}</ul></div>
        </>
      )}
    </section>
  )
}
