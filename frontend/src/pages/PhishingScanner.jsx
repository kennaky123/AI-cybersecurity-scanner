import { useState } from 'react'
import ExplanationPanel from '../components/ExplanationPanel.jsx'
import SecurityTutorPanel from '../components/SecurityTutorPanel.jsx'
import URLAnalysisPanel from '../components/URLAnalysisPanel.jsx'
import HTMLAnalysisPanel from '../components/HTMLAnalysisPanel.jsx'
import JavaScriptAnalysisPanel from '../components/JavaScriptAnalysisPanel.jsx'
import ThreatIntelPanel from '../components/ThreatIntelPanel.jsx'
import RiskReportPanel from '../components/RiskReportPanel.jsx'
import SandboxAnalysisPanel from '../components/SandboxAnalysisPanel.jsx'
import VisualAnalysisPanel from '../components/VisualAnalysisPanel.jsx'
import DownloadAnalysisPanel from '../components/DownloadAnalysisPanel.jsx'
import FriendlyAIPanel from '../components/FriendlyAIPanel.jsx'
import PhishingSecurityDashboard from '../components/PhishingSecurityDashboard.jsx'
import {
  analyzePhishingDownloads,
  analyzePhishingHtml,
  analyzePhishingJavascript,
  analyzePhishingSandbox,
  analyzePhishingUrl,
  analyzePhishingVisual,
  lookupThreatIntelligence,
} from '../services/api.js'

const importantFeatures = [
  'url_length',
  'domain_length',
  'num_subdomains',
  'uses_https',
  'contains_ip_address',
  'contains_at_symbol',
  'contains_suspicious_port',
  'num_parameters',
  'url_entropy',
  'suspicious_keyword_count',
]

const sampleUrls = [
  { url: 'https://google.com', label: 'Google (An toàn)', tag: 'safe-tag' },
  { url: 'https://github.com', label: 'GitHub (An toàn)', tag: 'safe-tag' },
  { url: 'http://paypal-security-account-alert.xyz/login', label: 'Paypal Giả mạo', tag: 'danger-tag' },
  { url: 'http://192.168.1.105:8080/bank/update.php', label: 'IP lạ + Cổng', tag: 'danger-tag' },
]

function featureLabel(name) {
  const map = {
    url_length: 'Chiều dài URL',
    domain_length: 'Chiều dài Domain',
    num_subdomains: 'Số tên miền phụ',
    uses_https: 'Giao thức HTTPS',
    contains_ip_address: 'Địa chỉ IP tĩnh',
    contains_at_symbol: 'Ký tự @ nhạy cảm',
    contains_suspicious_port: 'Cổng bất thường',
    num_parameters: 'Số tham số URL',
    url_entropy: 'Độ hỗn loạn Entropy',
    suspicious_keyword_count: 'Từ khóa đáng ngờ',
  }
  return map[name] || name.replaceAll('_', ' ').replace(/^./, (c) => c.toUpperCase())
}

function formatFeatureValue(name, val) {
  if (name === 'uses_https') return val ? '✓ Có (HTTPS)' : '✗ Không (HTTP)'
  if (name === 'contains_ip_address') return val ? '⚠ Phát hiện IP' : '✓ Tên miền'
  if (name === 'contains_at_symbol') return val ? '⚠ Có chứa @' : '✓ Bình thường'
  if (name === 'contains_suspicious_port') return val ? '⚠ Cổng phi chuẩn' : '✓ Cổng chuẩn (80/443)'
  if (name === 'url_entropy' && typeof val === 'number') return val.toFixed(2)
  return String(val ?? '—')
}

export default function PhishingScanner() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)

  // Sub-modules state
  const [htmlResult, setHtmlResult] = useState(null)
  const [htmlLoading, setHtmlLoading] = useState(false)
  const [htmlError, setHtmlError] = useState('')
  const [javascriptResult, setJavascriptResult] = useState(null)
  const [javascriptLoading, setJavascriptLoading] = useState(false)
  const [javascriptError, setJavascriptError] = useState('')
  const [threatIntelResult, setThreatIntelResult] = useState(null)
  const [threatIntelLoading, setThreatIntelLoading] = useState(false)
  const [threatIntelError, setThreatIntelError] = useState('')
  const [sandboxResult, setSandboxResult] = useState(null)
  const [sandboxLoading, setSandboxLoading] = useState(false)
  const [sandboxError, setSandboxError] = useState('')
  const [visualResult, setVisualResult] = useState(null)
  const [visualLoading, setVisualLoading] = useState(false)
  const [visualError, setVisualError] = useState('')
  const [downloadResult, setDownloadResult] = useState(null)
  const [downloadLoading, setDownloadLoading] = useState(false)
  const [downloadError, setDownloadError] = useState('')

  // View state
  const [viewMode, setViewMode] = useState('simple')
  const [activeTab, setActiveTab] = useState('dashboard')

  async function triggerScan(targetUrl) {
    const clean = (targetUrl || url).trim()
    if (!clean) return
    setLoading(true)
    setError('')
    setResult(null)
    setHtmlResult(null)
    setHtmlError('')
    setJavascriptResult(null)
    setJavascriptError('')
    setThreatIntelResult(null)
    setThreatIntelError('')
    setSandboxResult(null)
    setSandboxError('')
    setVisualResult(null)
    setVisualError('')
    setDownloadResult(null)
    setDownloadError('')
    try {
      const res = await analyzePhishingUrl(clean)
      setResult(res)
    } catch (requestError) {
      setError(requestError.message || 'Không thể phân tích URL này.')
    } finally {
      setLoading(false)
    }
  }

  function handleSubmit(event) {
    event.preventDefault()
    triggerScan()
  }

  function handleSelectSample(sampleUrl) {
    setUrl(sampleUrl)
    triggerScan(sampleUrl)
  }

  function handleCopyUrl() {
    if (!result?.url) return
    navigator.clipboard.writeText(result.url)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  async function handleDownloadAnalysis() {
    setDownloadLoading(true)
    setDownloadError('')
    try {
      setDownloadResult(await analyzePhishingDownloads(url.trim()))
    } catch (requestError) {
      setDownloadError(requestError.message || 'Không thể phân tích các tệp tải xuống.')
    } finally {
      setDownloadLoading(false)
    }
  }

  async function handleVisualAnalysis() {
    setVisualLoading(true)
    setVisualError('')
    try {
      setVisualResult(await analyzePhishingVisual(url.trim()))
    } catch (requestError) {
      setVisualError(requestError.message || 'Không thể phân tích ảnh chụp an toàn.')
    } finally {
      setVisualLoading(false)
    }
  }

  async function handleSandboxAnalysis() {
    setSandboxLoading(true)
    setSandboxError('')
    try {
      setSandboxResult(await analyzePhishingSandbox(url.trim()))
    } catch (requestError) {
      setSandboxError(requestError.message || 'Không thể chạy phân tích hành vi cách ly.')
    } finally {
      setSandboxLoading(false)
    }
  }

  async function handleThreatIntelLookup() {
    setThreatIntelLoading(true)
    setThreatIntelError('')
    try {
      setThreatIntelResult(await lookupThreatIntelligence('URL', url.trim()))
    } catch (requestError) {
      setThreatIntelError(requestError.message || 'Không thể truy vấn các nguồn tình báo mối đe dọa.')
    } finally {
      setThreatIntelLoading(false)
    }
  }

  async function handleJavascriptAnalysis() {
    setJavascriptLoading(true)
    setJavascriptError('')
    try {
      setJavascriptResult(await analyzePhishingJavascript(url.trim()))
    } catch (requestError) {
      setJavascriptError(requestError.message || 'Không thể kiểm tra JavaScript an toàn.')
    } finally {
      setJavascriptLoading(false)
    }
  }

  async function handleHtmlAnalysis() {
    setHtmlLoading(true)
    setHtmlError('')
    try {
      setHtmlResult(await analyzePhishingHtml(url.trim()))
    } catch (requestError) {
      setHtmlError(requestError.message || 'Không thể tải HTML an toàn.')
    } finally {
      setHtmlLoading(false)
    }
  }

  function handleExportJSON() {
    if (!result) return
    const blob = new Blob(
      [
        JSON.stringify(
          {
            result,
            htmlResult,
            javascriptResult,
            threatIntelResult,
            sandboxResult,
            visualResult,
            downloadResult,
          },
          null,
          2
        ),
      ],
      { type: 'application/json' }
    )
    const exportUrl = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = exportUrl
    anchor.download = `phishing_report_${Date.now()}.json`
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(exportUrl)
  }

  function handlePrintReport() {
    window.print()
  }

  const isPhishing = result?.prediction === 'PHISHING'
  const isSafe = result?.prediction === 'BENIGN' || result?.prediction === 'SAFE'

  return (
    <section className="scanner-page bento-container">
      {/* Page Header */}
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">Phòng thủ theo chiều sâu & ML ngoại tuyến</p>
          <h1>Quét Phishing & An toàn Web</h1>
          <p className="lead">Kiểm tra URL bằng mô hình trí tuệ nhân tạo, phân tích cấu trúc DOM HTML, mã JavaScript và tình báo mối đe dọa thời gian thực.</p>
        </div>
        {result && (
          <div style={{ display: 'flex', gap: '8px' }}>
            <button type="button" onClick={handleExportJSON} className="secondary-button">
              📥 Xuất JSON
            </button>
            <button type="button" onClick={handlePrintReport} className="primary-button">
              🖨️ In / PDF
            </button>
          </div>
        )}
      </div>

      {/* Linear Command Bar Input */}
      <form onSubmit={handleSubmit}>
        <div className="command-bar">
          <span className="command-icon">⌕</span>
          <input
            id="phishing-url"
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Dán liên kết cần kiểm tra (ví dụ: https://example.com)..."
            autoComplete="url"
            required
            disabled={loading}
            className="command-input"
          />
          <button type="submit" disabled={loading || !url.trim()} className="command-btn">
            {loading ? 'Đang quét…' : (
              <>
                Quét URL
                <kbd className="command-kbd">↵</kbd>
              </>
            )}
          </button>
        </div>

        {/* Quick Sample Test Chips */}
        <div className="sample-chips-row">
          <span className="sample-chips-label">Thử nhanh mẫu:</span>
          {sampleUrls.map((s) => (
            <button
              key={s.url}
              type="button"
              className={`sample-chip ${s.tag}`}
              onClick={() => handleSelectSample(s.url)}
              disabled={loading}
            >
              {s.label}
            </button>
          ))}
        </div>
      </form>

      {error && <div className="scanner-error" role="alert">{error}</div>}

      {/* Bento Grid Results */}
      {result && (
        <div className="scan-result" aria-live="polite">
          {/* Row 1: Primary Diagnosis (Asymmetric Bento 7 / 5) */}
          <div className="bento-row">
            {/* Hero Verdict Cell */}
            <div className={`bento-cell bento-col-7 bento-cell-hero ${isPhishing ? 'bento-cell-danger' : 'bento-cell-safe'}`}>
              <div className="bento-cell-header">
                <span className={`verdict-status-badge ${isPhishing ? 'danger' : 'safe'}`}>
                  <span className={`pulse-indicator ${isPhishing ? 'danger' : 'safe'}`} />
                  {isPhishing ? 'Cảnh báo: Phát hiện Phishing' : 'Xác minh: Trang web An toàn'}
                </span>
                <span className={`risk-pill ${result.risk_level.toLowerCase()}`}>{result.risk_level}</span>
              </div>

              <div className="verdict-target-url">
                <span>{result.url}</span>
                <button
                  type="button"
                  onClick={handleCopyUrl}
                  className="secondary-button"
                  style={{ height: '28px', padding: '0 8px', fontSize: '0.72rem' }}
                >
                  {copied ? '✓ Đã chép' : 'Sao chép'}
                </button>
              </div>

              <div className="verdict-meta-row">
                <div className="verdict-meta-item">
                  <span>Giao thức:</span>
                  <strong style={{ color: result.features.uses_https ? 'var(--color-safe)' : 'var(--color-warning)' }}>
                    {result.features.uses_https ? 'HTTPS (Mã hóa)' : 'HTTP (Không mã hóa)'}
                  </strong>
                </div>
                <div className="verdict-meta-item">
                  <span>Xác suất phishing:</span>
                  <strong>{(result.probability * 100).toFixed(2)}%</strong>
                </div>
                <div className="verdict-meta-item">
                  <span>Mô hình:</span>
                  <code>Random Forest + Heuristics</code>
                </div>
              </div>
            </div>

            {/* Risk Score & Quick Actions Cell */}
            <div className="bento-cell bento-col-5">
              <div className="bento-gauge-box">
                <span className="bento-feature-pill-label">Chỉ số rủi ro tổng hợp</span>
                <div className="bento-score-display">
                  <span
                    className="bento-score-number"
                    style={{
                      color:
                        result.risk_score >= 70
                          ? 'var(--color-danger)'
                          : result.risk_score >= 35
                          ? 'var(--color-warning)'
                          : 'var(--color-safe)',
                    }}
                  >
                    {result.risk_score}
                  </span>
                  <span className="bento-score-total">/100</span>
                </div>

                <div className="bento-score-progress">
                  <div
                    className="bento-score-progress-fill"
                    style={{
                      width: `${Math.min(100, Math.max(5, result.risk_score))}%`,
                      backgroundColor:
                        result.risk_score >= 70
                          ? 'var(--color-danger)'
                          : result.risk_score >= 35
                          ? 'var(--color-warning)'
                          : 'var(--color-safe)',
                    }}
                  />
                </div>

                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--color-muted)' }}>
                  {result.risk_score >= 70
                    ? 'Nguy cơ lừa đảo cao. Khuyến cáo không truy cập hoặc điền thông tin.'
                    : result.risk_score >= 35
                    ? 'Độ tin cậy ở mức trung bình. Hãy cẩn trọng kiểm tra nguồn gốc URL.'
                    : 'Không phát hiện dấu hiệu bất thường về mặt kỹ thuật và danh tiếng.'}
                </p>
              </div>
            </div>
          </div>

          {/* Row 2: URL Micro-Features (8 cols) & View Switcher (4 cols) */}
          <div className="bento-row">
            {/* Feature Pills Bento */}
            <div className="bento-cell bento-col-8">
              <div className="bento-cell-header">
                <h2 className="bento-cell-title">Đặc trưng kỹ thuật URL (Trích xuất ML)</h2>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>10 chỉ số</span>
              </div>
              <div className="bento-feature-pill-grid">
                {importantFeatures.map((name) => (
                  <div key={name} className="bento-feature-pill">
                    <span className="bento-feature-pill-label">{featureLabel(name)}</span>
                    <span className="bento-feature-pill-val">{formatFeatureValue(name, result.features[name])}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* View Mode & Guidance */}
            <div className="bento-cell bento-col-4" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div className="bento-cell-header">
                  <h2 className="bento-cell-title">Chế độ phân tích</h2>
                </div>
                <div className="mode-toggle-buttons" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  <button
                    type="button"
                    className={`mode-btn ${viewMode === 'simple' ? 'active' : ''}`}
                    onClick={() => setViewMode('simple')}
                  >
                    🟢 Dễ hiểu
                  </button>
                  <button
                    type="button"
                    className={`mode-btn ${viewMode === 'advanced' ? 'active' : ''}`}
                    onClick={() => setViewMode('advanced')}
                  >
                    🔬 Chuyên sâu
                  </button>
                </div>
              </div>

              <div style={{ marginTop: '16px', padding: '12px', background: 'var(--color-paper-3)', borderRadius: 'var(--radius-control)', border: '1px solid var(--color-rule)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-accent)', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                  💡 GỢI Ý BẢO MẬT
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--color-ink-2)' }}>
                  {isPhishing
                    ? 'Chặn kết nối đến tên miền này ngay lập tức trên hệ thống tường lửa / DNS.'
                    : 'Trang web an toàn. Có thể tiếp tục duyệt web bình thường.'}
                </span>
              </div>
            </div>
          </div>

          {/* Simple Mode View */}
          {viewMode === 'simple' && (
            <div style={{ marginTop: '8px' }}>
              <FriendlyAIPanel result={result} onSwitchToAdvanced={() => setViewMode('advanced')} />
            </div>
          )}

          {/* Advanced Mode: Linear Bento Subtabs */}
          {viewMode === 'advanced' && (
            <div style={{ marginTop: '8px' }}>
              <nav className="linear-subtabs-nav" aria-label="Các mô-đun phân tích">
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
                  onClick={() => setActiveTab('dashboard')}
                >
                  🛡️ Bảng điều khiển
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'explanation' ? 'active' : ''}`}
                  onClick={() => setActiveTab('explanation')}
                >
                  🤖 AI Giải thích
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'url' ? 'active' : ''}`}
                  onClick={() => setActiveTab('url')}
                >
                  🌐 URL & Domain
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'html' ? 'active' : ''}`}
                  onClick={() => setActiveTab('html')}
                >
                  📄 HTML & Biểu mẫu
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'javascript' ? 'active' : ''}`}
                  onClick={() => setActiveTab('javascript')}
                >
                  ⚡ JavaScript
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'threat' ? 'active' : ''}`}
                  onClick={() => setActiveTab('threat')}
                >
                  🛰️ Tình báo (Intel)
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'sandbox' ? 'active' : ''}`}
                  onClick={() => setActiveTab('sandbox')}
                >
                  📦 Sandbox
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'downloads' ? 'active' : ''}`}
                  onClick={() => setActiveTab('downloads')}
                >
                  💾 Tải xuống
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'visual' ? 'active' : ''}`}
                  onClick={() => setActiveTab('visual')}
                >
                  📸 Nhận diện ảnh
                </button>
                <button
                  type="button"
                  className={`linear-subtab-btn ${activeTab === 'tutor' ? 'active' : ''}`}
                  onClick={() => setActiveTab('tutor')}
                >
                  📚 Hướng dẫn
                </button>
              </nav>

              {/* Active Tab Panel Content */}
              <div className="bento-cell" style={{ padding: '24px' }}>
                {activeTab === 'dashboard' && (
                  <PhishingSecurityDashboard
                    result={result}
                    htmlResult={htmlResult}
                    javascriptResult={javascriptResult}
                    sandboxResult={sandboxResult}
                    downloadResult={downloadResult}
                    threatIntelResult={threatIntelResult}
                    visualResult={visualResult}
                  />
                )}
                {activeTab === 'explanation' && (
                  <ExplanationPanel explanation={result.explanation} riskLabel="phishing" />
                )}
                {activeTab === 'url' && (
                  <URLAnalysisPanel urlAnalysis={result.url_analysis} domainAnalysis={result.domain_analysis} />
                )}
                {activeTab === 'html' && (
                  <HTMLAnalysisPanel result={htmlResult} loading={htmlLoading} error={htmlError} onAnalyze={handleHtmlAnalysis} />
                )}
                {activeTab === 'javascript' && (
                  <JavaScriptAnalysisPanel result={javascriptResult} loading={javascriptLoading} error={javascriptError} onAnalyze={handleJavascriptAnalysis} />
                )}
                {activeTab === 'threat' && (
                  <ThreatIntelPanel result={threatIntelResult} loading={threatIntelLoading} error={threatIntelError} onLookup={handleThreatIntelLookup} />
                )}
                {activeTab === 'sandbox' && (
                  <SandboxAnalysisPanel result={sandboxResult} loading={sandboxLoading} error={sandboxError} onAnalyze={handleSandboxAnalysis} />
                )}
                {activeTab === 'downloads' && (
                  <DownloadAnalysisPanel result={downloadResult} loading={downloadLoading} error={downloadError} onAnalyze={handleDownloadAnalysis} />
                )}
                {activeTab === 'visual' && (
                  <VisualAnalysisPanel result={visualResult} loading={visualLoading} error={visualError} onAnalyze={handleVisualAnalysis} />
                )}
                {activeTab === 'tutor' && (
                  <SecurityTutorPanel education={result.education} />
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
