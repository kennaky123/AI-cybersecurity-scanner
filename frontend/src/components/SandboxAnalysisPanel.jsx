import { t, translateStatus, translateEvidence } from '../services/translator.js';

export default function SandboxAnalysisPanel({ result, loading, error, onAnalyze }) {
  return (
    <section className="result-section sandbox-analysis-panel">
      <div className="explanation-heading">
        <div><h2>Giai đoạn 6: Phân tích hành vi trình duyệt</h2><p>Cần provider container/VM được cách ly. Cấu hình mặc định không khởi chạy trình duyệt trên máy này.</p></div>
        <button type="button" className="secondary-button" onClick={onAnalyze} disabled={loading}>{loading ? 'Đang kiểm tra sandbox…' : 'Phân tích hành vi'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && <>
        <div className="metric-grid html-metrics"><article><span>{t('Status')}</span><strong>{translateStatus(result.status)}</strong></article><article><span>{t('Telemetry')}</span><strong>{result.telemetry.length}</strong></article><article><span>{t('Downloads')}</span><strong>{result.downloads.length}</strong></article></div>
        <div className="feature-grid"><div><span>{t('Redirect chain')}</span><code>{result.redirect_chain.length}</code></div><div><span>{t('External domains')}</span><code>{result.external_domains.length}</code></div><div><span>{t('Execution policy')}</span><code>{translateStatus(result.downloads.every((item) => item.execution_blocked) ? 'Blocked' : 'Review')}</code></div></div>
        <div className="analysis-explanations"><h3>{t('Sandbox status')}</h3><ul>{result.explanation.map((item, index) => <li key={index}>{translateEvidence(item)}</li>)}</ul></div>
      </>}
    </section>
  )
}
