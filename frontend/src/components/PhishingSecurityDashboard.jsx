import { useMemo, useState } from 'react'
import { t } from '../services/translator.js'


const tabs = [
  ['overview', 'Tổng quan'], ['url', 'URL'], ['domain', 'Domain'], ['html', 'HTML'],
  ['javascript', 'JavaScript'], ['network', 'Network'], ['sandbox', 'Sandbox'],
  ['downloads', 'Tải xuống'], ['threat', 'Tình báo mối đe dọa'], ['evidence', 'Bằng chứng'],
]

function values(items = []) {
  return items.length ? items : ['None available']
}

function List({ items = [], className = '' }) {
  return <ul className={`security-list ${className}`}>{values(items).map((item, index) => <li key={`${index}-${String(item)}`}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>)}</ul>
}

function Metric({ label, value, tone = '' }) {
  return <article className={`security-metric ${tone}`}><span>{label}</span><strong>{value}</strong></article>
}

function EvidenceGroup({ title, tone, items }) {
  return <section className={`evidence-group ${tone}`}><h3>{title}</h3><List items={items} /></section>
}

function FeatureGrid({ features = {} }) {
  return <div className="security-feature-grid">{Object.entries(features).filter(([, value]) => !Array.isArray(value) && typeof value !== 'object').map(([key, value]) => <div key={key}><span>{key.replaceAll('_', ' ')}</span><code>{String(value)}</code></div>)}</div>
}

export default function PhishingSecurityDashboard({ result, htmlResult, javascriptResult, sandboxResult, downloadResult, threatIntelResult, visualResult }) {
  const [activeTab, setActiveTab] = useState('overview')
  const report = result?.risk_report || {}
  const urlAnalysis = result?.url_analysis || {}
  const domainAnalysis = result?.domain_analysis || {}
  const html = htmlResult || result?.html_analysis || {}
  const javascript = javascriptResult || result?.javascript_analysis || {}
  const intel = threatIntelResult?.results || result?.threat_intelligence || []
  const observed = useMemo(() => [
    ...(report.evidence || []).filter((item) => item.category === 'OBSERVED').map((item) => `${item.indicator}: ${item.explanation}`),
    ...(report.observed_behavior || []),
    ...(sandboxResult?.redirect_chain || []).map((item) => `Browser redirected to ${item.url || item.destination || 'unknown destination'}.`),
  ], [report.evidence, report.observed_behavior, sandboxResult?.redirect_chain])
  const potential = useMemo(() => [
    ...(report.potential_impact || []),
    ...(javascript.potential_capabilities || []),
  ], [report.potential_impact, javascript.potential_capabilities])
  const intelEvidence = useMemo(() => intel.filter((item) => item.status === 'found').flatMap((item) => item.evidence?.map((evidence) => `${item.provider}: ${evidence}`) || []), [intel])
  const modelEvidence = useMemo(() => [
    `Phishing probability: ${((result?.probability || 0) * 100).toFixed(2)}%.`,
    ...(report.evidence || []).filter((item) => item.category === 'MODEL_PREDICTION').map((item) => item.explanation),
  ], [result?.probability, report.evidence])
  const categories = [
    [t('Credential Theft'), (html.credential_fields?.length || 0) + (html.external_submissions?.length || 0), 'potential'],
    [t('Brand Impersonation'), visualResult?.brand_impersonation ? 1 : 0, 'danger'],
    [t('Suspicious JavaScript'), (javascript.suspicious_behaviors?.length || 0) + (javascript.observed_static_indicators?.length || 0), 'warning'],
    [t('Suspicious Redirect'), (javascript.redirects?.length || 0) + (sandboxResult?.redirect_chain?.length || 0), 'warning'],
    [t('Malicious Download'), downloadResult?.downloads?.filter((item) => ['HIGH', 'CRITICAL'].includes(item.risk)).length || 0, 'danger'],
    [t('Threat Intelligence'), intel.filter((item) => item.status === 'found').length, 'danger'],
  ]

  function tabContent() {
    if (activeTab === 'overview') return <>
      <div className="security-metric-grid">
        <Metric label="Phân loại" value={report.classification || 'CHƯA BIẾT'} tone={report.classification === 'PHISHING' ? 'danger' : ''} />
        <Metric label="Điểm rủi ro" value={`${report.risk_score ?? '—'}/100`} />
        <Metric label="Độ tin cậy" value={report.confidence == null ? '—' : `${(report.confidence * 100).toFixed(0)}%`} />
        <Metric label="Mức độ" value={report.severity || 'CHƯA BIẾT'} tone={report.severity === 'CRITICAL' ? 'danger' : ''} />
      </div>
      <h3 className="dashboard-subtitle">Nhóm mối đe dọa</h3>
      <div className="threat-category-grid">{categories.map(([name, count, tone]) => <article className={`threat-category ${tone}`} key={name}><span>{name}</span><strong>{count}</strong></article>)}</div>
      <div className="evidence-columns"><EvidenceGroup title={t('Observed Behavior')} tone="observed" items={observed} /><EvidenceGroup title={t('Potential Capability')} tone="potential" items={potential} /><EvidenceGroup title={t('Threat Intelligence')} tone="intel" items={intelEvidence} /><EvidenceGroup title={t('Model Prediction')} tone="model" items={modelEvidence} /></div>
      <div className="recommendation-box"><h3>{t('Recommended next steps')}</h3><List items={report.recommendations} /></div>
    </>
    if (activeTab === 'url') return <AnalysisTab title="Phân tích URL"><FeatureGrid features={urlAnalysis.features} /><List items={urlAnalysis.explanation} /></AnalysisTab>
    if (activeTab === 'domain') return <AnalysisTab title="Phân tích tên miền"><FeatureGrid features={domainAnalysis.features} /><List items={domainAnalysis.explanation} /></AnalysisTab>
    if (activeTab === 'html') return <AnalysisTab title="Phân tích HTML"><FeatureGrid features={{ html_score: html.html_score, forms: html.forms?.length || 0, credential_fields: html.credential_fields?.length || 0, external_submissions: html.external_submissions?.length || 0, iframes: html.iframes?.length || 0 }} /><EvidenceGroup title="Chỉ báo HTML" tone="observed" items={html.indicators} /><List items={html.explanation} /></AnalysisTab>
    if (activeTab === 'javascript') return <AnalysisTab title="Phân tích JavaScript"><FeatureGrid features={{ javascript_score: javascript.javascript_score, APIs: javascript.apis?.length || 0, redirects: javascript.redirects?.length || 0, obfuscation: javascript.obfuscation?.detected ? 'observed' : 'not observed' }} /><EvidenceGroup title="Các chỉ báo tĩnh quan sát được" tone="observed" items={javascript.observed_static_indicators} /><EvidenceGroup title="Khả năng tiềm ẩn" tone="potential" items={javascript.potential_capabilities} /><List items={javascript.explanation} /></AnalysisTab>
    if (activeTab === 'network') return <AnalysisTab title="Phân tích mạng"><EvidenceGroup title="Chỉ báo mạng JavaScript" tone="observed" items={javascript.network_indicators} /><EvidenceGroup title="Tên miền ngoài sandbox" tone="observed" items={sandboxResult?.external_domains} /><List items={sandboxResult?.telemetry?.map((event) => `${event.event_type}: ${event.source} → ${event.destination || 'n/a'}`)} /></AnalysisTab>
    if (activeTab === 'sandbox') return <AnalysisTab title="Hành vi sandbox"><FeatureGrid features={{ status: sandboxResult?.status || 'not requested', telemetry: sandboxResult?.telemetry?.length || 0, screenshots: sandboxResult?.screenshots?.length || 0, downloads: sandboxResult?.downloads?.length || 0 }} /><EvidenceGroup title="Hành vi quan sát được" tone="observed" items={sandboxResult?.events?.map((event) => `${event.event_type}: ${event.source}`)} /><List items={sandboxResult?.explanation} /></AnalysisTab>
    if (activeTab === 'downloads') return <AnalysisTab title="Phân tích tải xuống"><FeatureGrid features={{ status: downloadResult?.status || 'not requested', website_risk: downloadResult?.website_risk || '—', downloads: downloadResult?.downloads?.length || 0 }} /><EvidenceGroup title="Bằng chứng tải xuống" tone="observed" items={downloadResult?.evidence} /><List items={downloadResult?.potential_impact} /></AnalysisTab>
    if (activeTab === 'threat') return <AnalysisTab title="Tình báo mối đe dọa"><div className="intel-table">{values(intel).map((item, index) => <div key={`${item.provider || 'provider'}-${index}`}><strong>{item.provider || 'unknown'}</strong><span>{item.status || 'unknown'}</span><small>{item.evidence?.join(' ') || 'No evidence supplied.'}</small></div>)}</div></AnalysisTab>
    return <AnalysisTab title="Bằng chứng"><div className="evidence-columns"><EvidenceGroup title={t('Observed Behavior')} tone="observed" items={observed} /><EvidenceGroup title={t('Potential Capability')} tone="potential" items={potential} /><EvidenceGroup title={t('Threat Intelligence')} tone="intel" items={intelEvidence} /><EvidenceGroup title={t('Model Prediction')} tone="model" items={modelEvidence} /></div></AnalysisTab>
  }

  return <section className="security-dashboard result-section"><div className="dashboard-header"><div><span className="eyebrow">{t('Phishing security dashboard')}</span><h2>{t('Explainable website assessment')}</h2><p>Bằng chứng được phân tách theo những gì quan sát được, những gì có thể xảy ra, những gì nhà cung cấp báo cáo và những gì mô hình ML dự đoán.</p></div><span className={`risk-pill ${(report.severity || 'low').toLowerCase()}`}>{report.classification || 'UNKNOWN'}</span></div><div className="dashboard-tabs" role="tablist">{tabs.map(([id, label]) => <button type="button" role="tab" aria-selected={activeTab === id} className={activeTab === id ? 'active' : ''} key={id} onClick={() => setActiveTab(id)}>{label}</button>)}</div><div className="dashboard-content">{tabContent()}</div></section>
}

function AnalysisTab({ title, children }) {
  return <div className="analysis-tab"><h3 className="dashboard-subtitle">{title}</h3>{children}</div>
}
