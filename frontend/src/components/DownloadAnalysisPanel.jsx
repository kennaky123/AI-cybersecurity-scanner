import { t, translateStatus, translateEvidence } from '../services/translator.js';

export default function DownloadAnalysisPanel({ result, loading, error, onAnalyze }) {
  return (
    <section className="result-section download-analysis-panel">
      <div className="explanation-heading">
        <div><h2>{t('Phase 8: Website Download Analysis')}</h2><p>Chỉ những tệp thực sự được sandbox quan sát mới được phân tích. Các tệp tải xuống không bao giờ được thực thi.</p></div>
        <button type="button" className="secondary-button" onClick={onAnalyze} disabled={loading}>{loading ? 'Đang kiểm tra tệp tải xuống…' : 'Phân tích tệp tải xuống'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && <>
        <div className="metric-grid html-metrics"><article><span>{t('Sandbox status')}</span><strong>{translateStatus(result.status)}</strong></article><article><span>{t('Website risk')}</span><strong>{translateStatus(result.website_risk)}</strong></article><article><span>{t('Downloads')}</span><strong>{result.downloads.length}</strong></article></div>
        <div className="analysis-explanations"><h3>{t('Evidence')}</h3><ul>{result.evidence.map((item, index) => <li key={index}>{translateEvidence(item)}</li>)}</ul>{result.downloads.map((item, index) => <div className="download-item" key={`${item.file.sha256 || item.file.filename}-${index}`}><strong>{item.file.filename || 'tải xuống'}</strong><span>{item.file.file_type} · {translateStatus(item.risk)} · SHA-256 {item.file.sha256 || 'không rõ'}</span></div>)}</div>
      </>}
    </section>
  )
}
