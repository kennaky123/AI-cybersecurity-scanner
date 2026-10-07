import { t, translateStatus, translateEvidence } from '../services/translator.js';

export default function VisualAnalysisPanel({ result, loading, error, onAnalyze }) {
  return (
    <section className="result-section visual-analysis-panel">
      <div className="explanation-heading">
        <div><h2>Giai đoạn 7: Phân tích phishing bằng hình ảnh</h2><p>Dùng ảnh chụp từ sandbox cách ly. Độ giống hình ảnh chỉ hỗ trợ điều tra, không tự kết luận phishing.</p></div>
        <button type="button" className="secondary-button" onClick={onAnalyze} disabled={loading}>{loading ? 'Đang phân tích ảnh…' : 'Phân tích hình ảnh'}</button>
      </div>
      {error && <div className="scanner-error" role="alert">{error}</div>}
      {result && <>
        <div className="metric-grid html-metrics"><article><span>{t('Status')}</span><strong>{translateStatus(result.status)}</strong></article><article><span>{t('Brand')}</span><strong>{result.detected_brand || t('None')}</strong></article><article><span>{t('Visual similarity')}</span><strong>{(result.visual_similarity * 100).toFixed(0)}<small>%</small></strong></article></div>
        <div className="feature-grid"><div><span>{t('Logo detected')}</span><code>{translateStatus(result.logo_detected ? 'Yes' : 'No')}</code></div><div><span>{t('Login layout')}</span><code>{translateStatus(result.login_page_detected ? 'Yes' : 'No')}</code></div><div><span>{t('Domain matches brand')}</span><code>{translateStatus(result.domain_matches_brand === null ? 'Unknown' : result.domain_matches_brand ? 'Yes' : 'No')}</code></div><div><span>{t('Brand impersonation')}</span><code>{translateStatus(result.brand_impersonation ? 'Possible' : 'Not established')}</code></div></div>
        <div className="analysis-explanations"><h3>{t('Structured evidence')}</h3><ul>{result.evidence.map((item, index) => <li key={index}><strong>{t(item.category)}</strong> · {item.indicator}: {translateEvidence(item.explanation)}</li>)}</ul><ul>{result.explanation.map((item, index) => <li key={`explanation-${index}`}>{translateEvidence(item)}</li>)}</ul></div>
      </>}
    </section>
  )
}
