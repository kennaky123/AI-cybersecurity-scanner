function label(value) {
  return value.replaceAll('_', ' ').replace(/^./, (character) => character.toUpperCase())
}

export default function URLAnalysisPanel({ urlAnalysis, domainAnalysis }) {
  if (!urlAnalysis || !domainAnalysis) return null
  const visibleFeatures = [
    ['hostname_length', urlAnalysis.features.hostname_length],
    ['path_length', urlAnalysis.features.path_length],
    ['query_length', urlAnalysis.features.query_length],
    ['percent_encoding_count', urlAnalysis.features.percent_encoding_count],
    ['hostname_entropy', urlAnalysis.features.hostname_entropy],
    ['suspicious_tld', urlAnalysis.features.suspicious_tld ? 'Yes' : 'No'],
    ['ip_address', urlAnalysis.features.ip_address || 'None'],
    ['domain_age_status', urlAnalysis.features.domain_age_status],
    ['dns_status', urlAnalysis.features.dns_status],
    ['asn', urlAnalysis.features.asn || 'Unavailable'],
  ]
  return (
    <section className="result-section url-analysis-panel">
      <div className="explanation-heading">
        <div><h2>URL + Domain Analysis</h2><p>Phase 1 structured evidence. Domain age, DNS and ASN stay unknown when no provider is configured.</p></div>
        <span className={`risk-pill ${urlAnalysis.severity.toLowerCase()}`}>{urlAnalysis.severity} · {urlAnalysis.score}/100</span>
      </div>
      <div className="feature-grid">{visibleFeatures.map(([name, value]) => <div key={name}><span>{label(name)}</span><code>{String(value)}</code></div>)}</div>
      <div className="analysis-columns">
        <div><h3>Indicators</h3><ul>{urlAnalysis.indicators.length ? urlAnalysis.indicators.map((item) => <li key={item}>{label(item)}</li>) : <li>None above threshold</li>}</ul></div>
        <div><h3>Domain indicators</h3><ul>{domainAnalysis.indicators.length ? domainAnalysis.indicators.map((item) => <li key={item}>{label(item)}</li>) : <li>None above threshold</li>}</ul></div>
      </div>
      <div className="analysis-explanations"><h3>Why these indicators matter</h3><ul>{urlAnalysis.explanation.map((item, index) => <li key={index}>{item}</li>)}</ul></div>
    </section>
  )
}
