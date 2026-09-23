import { useEffect, useState } from 'react'
import ScanTable from '../components/ScanTable.jsx'
import { getScanHistory } from '../services/api.js'

export default function ScanHistory() {
  const [page, setPage] = useState(1)
  const [scanType, setScanType] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [sortOrder, setSortOrder] = useState('desc')
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [data, setData] = useState({ items: [], total: 0, total_pages: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const timeout = setTimeout(() => {
      setSearch(searchInput.trim())
      setPage(1)
    }, 300)
    return () => clearTimeout(timeout)
  }, [searchInput])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError('')
    getScanHistory({
      page,
      page_size: 15,
      scan_type: scanType,
      risk_level: riskLevel,
      search,
      sort_order: sortOrder,
    }, controller.signal)
      .then(setData)
      .catch((requestError) => {
        if (requestError.name !== 'AbortError') setError(requestError.message || 'Unable to load scan history.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [page, scanType, riskLevel, search, sortOrder])

  function updateFilter(setter, value) {
    setter(value)
    setPage(1)
  }

  const totalPages = Math.max(data.total_pages, 1)

  return (
    <section className="history-page">
      <p className="eyebrow">Audit trail</p>
      <h1>Scan History</h1>
      <p className="lead">Search, filter and review every completed scan.</p>

      <div className="history-toolbar">
        <input
          type="search"
          value={searchInput}
          onChange={(event) => setSearchInput(event.target.value)}
          placeholder="Search target, SHA-256 or prediction"
          aria-label="Search scan history"
        />
        <select value={scanType} onChange={(event) => updateFilter(setScanType, event.target.value)} aria-label="Filter by scan type">
          <option value="">All types</option>
          <option value="PHISHING">Phishing</option>
          <option value="MALWARE">Malware</option>
        </select>
        <select value={riskLevel} onChange={(event) => updateFilter(setRiskLevel, event.target.value)} aria-label="Filter by risk">
          <option value="">All risks</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select value={sortOrder} onChange={(event) => updateFilter(setSortOrder, event.target.value)} aria-label="Sort by date">
          <option value="desc">Newest first</option>
          <option value="asc">Oldest first</option>
        </select>
      </div>

      {error && <div className="scanner-error" role="alert">{error}</div>}
      <article className={`history-card ${loading ? 'is-loading' : ''}`}>
        <div className="card-heading"><h2>All scans</h2><span>{data.total} results</span></div>
        <ScanTable scans={data.items} />
        <div className="pagination">
          <button type="button" disabled={page <= 1 || loading} onClick={() => setPage((value) => value - 1)}>Previous</button>
          <span>Page {page} of {totalPages}</span>
          <button type="button" disabled={page >= totalPages || loading} onClick={() => setPage((value) => value + 1)}>Next</button>
        </div>
      </article>
    </section>
  )
}
