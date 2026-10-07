function Evidence({ item }) {
  return <li><strong>{item.category}</strong> · {item.indicator} <span>{item.explanation}</span></li>
}

export default function RiskReportPanel({ report }) {
  if (!report) return null
  return (
    <section className="result-section risk-report-panel">
      <div className="explanation-heading">
        <div><h2>Phase 5: Explainable Risk Engine</h2><p>Aggregate score combines analyzer evidence, threat intelligence and the existing ML probability. Thresholds are configurable triage policy, not scientific proof.</p></div>
        <span className={`risk-pill ${report.severity.toLowerCase()}`}>{report.classification} · {report.risk_score}/100</span>
      </div>
      <div className="metric-grid html-metrics"><article><span>Aggregate risk</span><strong>{report.risk_score}<small>/100</small></strong></article><article><span>Confidence</span><strong>{(report.confidence * 100).toFixed(0)}<small>%</small></strong></article><article><span>Evidence</span><strong>{report.evidence.length}</strong></article></div>
      <div className="risk-evidence"><h3>Why this result?</h3><ul>{report.evidence.map((item, index) => <Evidence item={item} key={`${item.category}-${item.indicator}-${index}`} />)}</ul></div>
      <div className="analysis-columns"><div><h3>Potential impact</h3><ul>{report.potential_impact.length ? report.potential_impact.map((item, index) => <li key={index}>{item}</li>) : <li>None inferred from available evidence.</li>}</ul></div><div><h3>Recommendations</h3><ul>{report.recommendations.map((item, index) => <li key={index}>{item}</li>)}</ul></div></div>
    </section>
  )
}
