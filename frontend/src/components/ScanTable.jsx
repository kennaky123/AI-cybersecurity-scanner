function formatDate(value) {
  if (!value) return '—'
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(normalized))
}

export default function ScanTable({ scans, emptyMessage = 'No scans found.' }) {
  if (!scans.length) return <div className="empty-state">{emptyMessage}</div>

  return (
    <div className="scan-table-wrap">
      <table className="scan-table">
        <thead>
          <tr>
            <th>Date</th>
            <th>Type</th>
            <th>Target</th>
            <th>Prediction</th>
            <th>Probability</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <td className="date-cell">{formatDate(scan.created_at)}</td>
              <td><span className={`type-badge ${scan.scan_type.toLowerCase()}`}>{scan.scan_type}</span></td>
              <td className="target-cell" title={scan.sha256 || scan.target}>
                <strong>{scan.target}</strong>
                {scan.sha256 && <code>{scan.sha256.slice(0, 14)}…</code>}
              </td>
              <td className={['MALWARE', 'PHISHING'].includes(scan.prediction) ? 'danger' : 'safe'}>
                {scan.prediction}
              </td>
              <td>{(scan.probability * 100).toFixed(1)}%</td>
              <td><span className={`risk-pill ${scan.risk_level.toLowerCase()}`}>{scan.risk_level}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
