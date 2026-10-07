import { useState } from 'react'

function formatDate(value) {
  if (!value) return '—'
  const normalized = value.includes('T') ? value : `${value.replace(' ', 'T')}Z`
  try {
    return new Intl.DateTimeFormat('vi-VN', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(normalized))
  } catch {
    return value
  }
}

export default function ScanTable({ scans, emptyMessage = 'Chưa có bản ghi quét nào được lưu.' }) {
  const [copiedId, setCopiedId] = useState(null)

  function handleCopy(text, id) {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1800)
  }

  if (!scans || !scans.length) {
    return (
      <div className="empty-state">
        <span style={{ fontSize: '1.5rem', display: 'block', marginBottom: '8px' }}>📂</span>
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="scan-table-wrap">
      <table className="scan-table">
        <thead>
          <tr>
            <th style={{ width: '160px' }}>Thời gian</th>
            <th style={{ width: '110px' }}>Loại quét</th>
            <th>Mục tiêu phân tích</th>
            <th style={{ width: '140px' }}>Kết luận ML</th>
            <th style={{ width: '110px' }}>Độ tin cậy</th>
            <th style={{ width: '110px' }}>Mức rủi ro</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const isDanger = ['MALWARE', 'PHISHING'].includes(scan.prediction)
            const isCopied = copiedId === scan.id
            return (
              <tr key={scan.id}>
                <td className="date-cell">{formatDate(scan.created_at)}</td>
                <td>
                  <span className={`type-badge ${scan.scan_type.toLowerCase()}`}>
                    {scan.scan_type === 'PHISHING' ? '⌁ Phishing' : '◈ Mã độc'}
                  </span>
                </td>
                <td className="target-cell">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
                    <strong title={scan.target}>{scan.target}</strong>
                    <button
                      type="button"
                      onClick={() => handleCopy(scan.sha256 || scan.target, scan.id)}
                      className="secondary-button"
                      style={{ height: '22px', padding: '0 6px', fontSize: '0.68rem', flexShrink: 0 }}
                      title="Sao chép địa chỉ / mã băm"
                    >
                      {isCopied ? '✓ Đã chép' : 'Chép'}
                    </button>
                  </div>
                  {scan.sha256 && (
                    <code title={scan.sha256}>
                      SHA-256: {scan.sha256.slice(0, 16)}…
                    </code>
                  )}
                </td>
                <td>
                  <span
                    className={`verdict-status-badge ${isDanger ? 'danger' : 'safe'}`}
                    style={{ fontSize: '0.72rem', padding: '3px 8px', letterSpacing: 0 }}
                  >
                    <span
                      className={`pulse-indicator ${isDanger ? 'danger' : 'safe'}`}
                      style={{ width: '6px', height: '6px' }}
                    />
                    {scan.prediction}
                  </span>
                </td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', fontWeight: 600 }}>
                    {(scan.probability * 100).toFixed(1)}%
                  </span>
                </td>
                <td>
                  <span className={`risk-pill ${scan.risk_level.toLowerCase()}`}>
                    {scan.risk_level}
                  </span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
