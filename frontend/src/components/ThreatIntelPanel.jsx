export default function ThreatIntelPanel({ result, loading, error, onLookup }) {
  return (
    <section className="result-section threat-intel-panel">
      <div className="explanation-heading">
        <div><h2>Giai đoạn 4: Tình báo mối đe dọa</h2><p>Kết quả provider chỉ là dữ liệu bổ sung. “Không khả dụng” và “không tìm thấy” không có nghĩa là chắc chắn an toàn.</p></div>
        <button type="button" className="secondary-button" onClick={onLookup} disabled={loading}>{loading ? 'Đang kiểm tra provider…' : 'Kiểm tra tình báo mối đe dọa'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && <div className="threat-results">{result.results.map((item) => (
        <article key={item.provider} className={`threat-result ${item.status}`}>
          <div><strong>{item.provider}</strong><span>{item.status.replaceAll('_', ' ')}</span></div>
          <small>Độ tin cậy: {(item.confidence * 100).toFixed(0)}%</small>
          <p>{item.evidence.join(' ')}</p>
        </article>
      ))}</div>}
    </section>
  )
}
