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
    getScanHistory(
      {
        page,
        page_size: 15,
        scan_type: scanType,
        risk_level: riskLevel,
        search,
        sort_order: sortOrder,
      },
      controller.signal
    )
      .then(setData)
      .catch((requestError) => {
        if (requestError.name !== 'AbortError') {
          setError(requestError.message || 'Không thể tải lịch sử quét.')
        }
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

  function handleResetFilters() {
    setSearchInput('')
    setSearch('')
    setScanType('')
    setRiskLevel('')
    setSortOrder('desc')
    setPage(1)
  }

  function handleExportHistory() {
    if (!data.items?.length) return
    const blob = new Blob([JSON.stringify(data.items, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `scan_history_page_${page}_${Date.now()}.json`
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(url)
  }

  const totalPages = Math.max(data.total_pages, 1)
  const hasActiveFilters = Boolean(search || scanType || riskLevel || sortOrder !== 'desc')

  return (
    <section className="history-page bento-container">
      {/* Page Heading */}
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">Nhật ký kiểm tra & Điều tra sự cố</p>
          <h1>Lịch sử quét an ninh mạng</h1>
          <p className="lead">Truy vấn, lọc và tra cứu toàn bộ hồ sơ kiểm tra URL phishing và tệp mã độc PE đã thực hiện.</p>
        </div>
        {data.items?.length > 0 && (
          <button type="button" onClick={handleExportHistory} className="secondary-button">
            📥 Xuất trang này (JSON)
          </button>
        )}
      </div>

      {/* Bento Stats Row */}
      <div className="bento-row">
        <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
          <span className="bento-feature-pill-label">Tổng lượt quét ghi nhận</span>
          <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.8rem', color: 'var(--color-accent)', display: 'block', marginTop: '4px' }}>
            {data.total}
          </strong>
        </div>
        <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
          <span className="bento-feature-pill-label">Số trang kết quả</span>
          <strong style={{ fontFamily: 'var(--font-display)', fontSize: '1.8rem', color: 'var(--color-ink)', display: 'block', marginTop: '4px' }}>
            {totalPages}
          </strong>
        </div>
        <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
          <span className="bento-feature-pill-label">Bộ lọc loại quét</span>
          <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '1.1rem', color: scanType ? 'var(--color-safe)' : 'var(--color-muted)', display: 'block', marginTop: '8px' }}>
            {scanType ? (scanType === 'PHISHING' ? '⌁ Phishing' : '◈ Mã độc PE') : 'Tất cả loại'}
          </strong>
        </div>
        <div className="bento-cell bento-col-3" style={{ padding: '16px' }}>
          <span className="bento-feature-pill-label">Bộ lọc mức rủi ro</span>
          <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '1.1rem', color: riskLevel ? 'var(--color-warning)' : 'var(--color-muted)', display: 'block', marginTop: '8px' }}>
            {riskLevel || 'Tất cả mức'}
          </strong>
        </div>
      </div>

      {/* Linear Search & Filter Toolbar */}
      <div className="history-toolbar">
        <input
          type="search"
          value={searchInput}
          onChange={(event) => setSearchInput(event.target.value)}
          placeholder="⌕ Tìm kiếm mục tiêu (URL, tên tệp), SHA-256 hoặc nhãn kết quả…"
          aria-label="Tìm kiếm lịch sử quét"
        />

        <select
          value={scanType}
          onChange={(event) => updateFilter(setScanType, event.target.value)}
          aria-label="Lọc theo loại quét"
        >
          <option value="">Tất cả loại quét</option>
          <option value="PHISHING">Quét Phishing</option>
          <option value="MALWARE">Quét Mã độc PE</option>
        </select>

        <select
          value={riskLevel}
          onChange={(event) => updateFilter(setRiskLevel, event.target.value)}
          aria-label="Lọc theo mức rủi ro"
        >
          <option value="">Tất cả mức rủi ro</option>
          <option value="LOW">Mức Thấp (Low)</option>
          <option value="MEDIUM">Mức Trung bình (Medium)</option>
          <option value="HIGH">Mức Cao (High)</option>
          <option value="CRITICAL">Nghiêm trọng (Critical)</option>
        </select>

        <select
          value={sortOrder}
          onChange={(event) => updateFilter(setSortOrder, event.target.value)}
          aria-label="Sắp xếp theo ngày"
        >
          <option value="desc">Mới nhất trước</option>
          <option value="asc">Cũ nhất trước</option>
        </select>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleResetFilters}
            className="secondary-button"
            style={{ height: '36px', padding: '0 12px', fontSize: '0.8rem' }}
          >
            ✕ Xóa bộ lọc
          </button>
        )}
      </div>

      {error && <div className="scanner-error" role="alert">{error}</div>}

      {/* Data Grid Bento Card */}
      <div className="bento-cell" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-heading">
          <h2 className="bento-cell-title">Danh sách kết quả kiểm tra</h2>
          <span>
            {loading ? 'Đang tải dữ liệu…' : `Hiển thị trang ${page} / ${totalPages} · Tổng số ${data.total} bản ghi`}
          </span>
        </div>

        <ScanTable scans={data.items} />

        <div className="pagination">
          <button
            type="button"
            disabled={page <= 1 || loading}
            onClick={() => setPage((value) => value - 1)}
            className="secondary-button"
          >
            ← Trang trước
          </button>
          <span>
            Trang {page} trên {totalPages}
          </span>
          <button
            type="button"
            disabled={page >= totalPages || loading}
            onClick={() => setPage((value) => value + 1)}
            className="secondary-button"
          >
            Trang sau →
          </button>
        </div>
      </div>
    </section>
  )
}
