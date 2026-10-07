import { useState } from 'react'
import { lookupMalwareBazaar, searchGoogleThreatIntel } from '../services/api.js'

export default function ThreatIntelDossierPanel({
  dossier,
  threatIntel,
  sha256,
  filename = '',
  bazaarIntel: initialBazaarIntel,
  bazaarAi: initialBazaarAi,
}) {
  const [activeTab, setActiveTab] = useState('bazaar')
  const [loading, setLoading] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)
  const [error, setError] = useState('')
  const [customBazaarData, setCustomBazaarData] = useState(null)
  const [googleData, setGoogleData] = useState(null)
  const [geminiKey, setGeminiKey] = useState(() => localStorage.getItem('gemini_api_key') || '')
  const [bazaarKey, setBazaarKey] = useState(() => localStorage.getItem('malwarebazaar_auth_key') || '')
  const [showKeyConfig, setShowKeyConfig] = useState(false)

  // Use custom refreshed data if available, or fall back to initial props/dossier
  const bData = customBazaarData?.bazaar_intel || initialBazaarIntel
  const bAi = customBazaarData?.ai_explanation || initialBazaarAi
  const sample = bData?.sample || {}

  const isMatched = dossier?.matched || bData?.matched || false
  const actor = dossier?.threat_actor
  const campaign = dossier?.campaign
  const attackChain = dossier?.attack_chain || []
  const mitreMatrix = dossier?.mitre_matrix || []
  const databases = dossier?.external_databases || []

  async function handleRefreshBazaar() {
    setLoading(true)
    setError('')
    try {
      if (geminiKey.trim()) localStorage.setItem('gemini_api_key', geminiKey.trim())
      if (bazaarKey.trim()) localStorage.setItem('malwarebazaar_auth_key', bazaarKey.trim())

      const response = await lookupMalwareBazaar(
        sha256,
        filename,
        geminiKey.trim() || null,
        bazaarKey.trim() || null
      )
      setCustomBazaarData(response)
    } catch (err) {
      setError(err.message || 'Không thể tra cứu MalwareBazaar.')
    } finally {
      setLoading(false)
    }
  }

  async function handleGoogleSearch() {
    setGoogleLoading(true)
    setError('')
    try {
      if (geminiKey.trim()) localStorage.setItem('gemini_api_key', geminiKey.trim())
      const response = await searchGoogleThreatIntel(
        sha256,
        filename,
        geminiKey.trim() || null
      )
      setGoogleData(response)
      setActiveTab('google')
    } catch (err) {
      setError(err.message || 'Không thể tra cứu Google Search OSINT.')
    } finally {
      setGoogleLoading(false)
    }
  }

  return (
    <section
      className="result-section threat-intel-panel"
      style={{
        marginTop: '1.25rem',
        border: isMatched ? '1px solid #ef4444' : '1px solid #334155',
        borderRadius: '8px',
        background: isMatched ? 'linear-gradient(180deg, #1c1322 0%, #0f172a 100%)' : '#0f172a',
        padding: '1.25rem',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.4rem' }}>{isMatched ? '🚨' : '🌐'}</span>
            <h2 style={{ margin: 0, fontSize: '1.25rem', color: isMatched ? '#f87171' : '#38bdf8' }}>
              {isMatched
                ? `Tình báo Mối đe dọa Quốc tế & MalwareBazaar: ${sample?.signature || actor?.name || 'Mã độc đã xác thực'}`
                : 'Tra cứu Cơ sở Dữ liệu Quốc tế MalwareBazaar (abuse.ch)'}
            </h2>
          </div>
          <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: '#94a3b8' }}>
            Đối chiếu mã băm với kho mã độc toàn cầu MalwareBazaar của tổ chức an ninh mạng abuse.ch và kích hoạt AI tổng hợp tình báo.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          {isMatched && (
            <span
              style={{
                padding: '0.35rem 0.75rem',
                background: '#991b1b',
                color: '#fef2f2',
                borderRadius: '9999px',
                fontSize: '0.75rem',
                fontWeight: 700,
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
                boxShadow: '0 0 12px rgba(220, 38, 38, 0.4)',
              }}
            >
              MALWAREBAZAAR VERIFIED
            </span>
          )}
          <button
            type="button"
            onClick={handleGoogleSearch}
            disabled={googleLoading}
            style={{
              padding: '0.45rem 0.9rem',
              background: googleLoading ? '#475569' : '#059669',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: googleLoading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            {googleLoading ? '⏳ Đang tra cứu Google OSINT…' : '🌐 Tra cứu Google Search (OSINT)'}
          </button>
          <button
            type="button"
            onClick={handleRefreshBazaar}
            disabled={loading}
            style={{
              padding: '0.45rem 0.9rem',
              background: loading ? '#475569' : '#0284c7',
              color: '#ffffff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            {loading ? '⏳ Đang tra cứu MalwareBazaar…' : '🔄 Tra cứu Trực tiếp & Phân tích AI'}
          </button>
        </div>
      </div>

      {/* API Key Toggle Form */}
      <div style={{ marginBottom: '1rem' }}>
        <button
          type="button"
          onClick={() => setShowKeyConfig(v => !v)}
          style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: '0.8rem', cursor: 'pointer', padding: 0 }}
        >
          {showKeyConfig ? 'Ẩn cấu hình API Key' : '⚙️ Tùy chọn: Nhập Gemini API Key hoặc MalwareBazaar Auth-Key'}
        </button>
        {showKeyConfig && (
          <div style={{ marginTop: '0.5rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.5rem' }}>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>Gemini API Key (AI Giải thích):</label>
              <input
                type="password"
                placeholder="AIzaSy..."
                value={geminiKey}
                onChange={e => setGeminiKey(e.target.value)}
                style={{ width: '100%', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid #334155', background: '#0b1120', color: '#f8fafc', fontSize: '0.85rem' }}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block', marginBottom: '0.2rem' }}>MalwareBazaar Auth-Key (nếu có tài khoản abuse.ch):</label>
              <input
                type="password"
                placeholder="Auth-Key từ abuse.ch..."
                value={bazaarKey}
                onChange={e => setBazaarKey(e.target.value)}
                style={{ width: '100%', padding: '0.4rem 0.6rem', borderRadius: '4px', border: '1px solid #334155', background: '#0b1120', color: '#f8fafc', fontSize: '0.85rem' }}
              />
            </div>
          </div>
        )}
      </div>

      {error && (
        <div style={{ padding: '0.75rem', background: '#450a0a', border: '1px solid #dc2626', borderRadius: '6px', color: '#fca5a5', fontSize: '0.85rem', marginBottom: '1rem' }}>
          {error}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.5rem', marginBottom: '1rem', overflowX: 'auto' }}>
        <button
          type="button"
          onClick={() => setActiveTab('bazaar')}
          style={{
            background: activeTab === 'bazaar' ? '#1e293b' : 'transparent',
            color: activeTab === 'bazaar' ? '#38bdf8' : '#94a3b8',
            border: 'none',
            padding: '0.4rem 0.8rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
          }}
        >
          🛡️ MalwareBazaar & AI Tình báo
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('google')}
          style={{
            background: activeTab === 'google' ? '#1e293b' : 'transparent',
            color: activeTab === 'google' ? '#10b981' : '#94a3b8',
            border: 'none',
            padding: '0.4rem 0.8rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
          }}
        >
          🌐 Google Search OSINT {googleData?.is_ai_grounded ? '✨' : ''}
        </button>
        {isMatched && (
          <>
            <button
              type="button"
              onClick={() => setActiveTab('actor')}
              style={{
                background: activeTab === 'actor' ? '#1e293b' : 'transparent',
                color: activeTab === 'actor' ? '#38bdf8' : '#94a3b8',
                border: 'none',
                padding: '0.4rem 0.8rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 600,
              }}
            >
              📋 Hồ sơ Nhóm Tin tặc
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('chain')}
              style={{
                background: activeTab === 'chain' ? '#1e293b' : 'transparent',
                color: activeTab === 'chain' ? '#38bdf8' : '#94a3b8',
                border: 'none',
                padding: '0.4rem 0.8rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 600,
              }}
            >
              ⚡ Chuỗi Tấn công
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('mitre')}
              style={{
                background: activeTab === 'mitre' ? '#1e293b' : 'transparent',
                color: activeTab === 'mitre' ? '#38bdf8' : '#94a3b8',
                border: 'none',
                padding: '0.4rem 0.8rem',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 600,
              }}
            >
              🎯 MITRE ATT&CK Matrix
            </button>
          </>
        )}
        <button
          type="button"
          onClick={() => setActiveTab('databases')}
          style={{
            background: activeTab === 'databases' ? '#1e293b' : 'transparent',
            color: activeTab === 'databases' ? '#38bdf8' : '#94a3b8',
            border: 'none',
            padding: '0.4rem 0.8rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.85rem',
            fontWeight: 600,
          }}
        >
          🌐 CSDL Quốc tế
        </button>
      </div>

      {/* TAB 1: MalwareBazaar & AI Tình báo */}
      {activeTab === 'bazaar' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* AI Explanation Box */}
          {bAi && (
            <div style={{ background: '#1e1b4b', border: '1px solid #6366f1', borderRadius: '8px', padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#c7d2fe', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>🤖 Trợ lý AI Phân tích Tình báo MalwareBazaar</span>
                </h3>
                <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem', background: bAi.is_ai_generated ? '#4338ca' : '#334155', color: '#e0e7ff', borderRadius: '4px' }}>
                  {bAi.is_ai_generated ? '✨ Gemini AI Phân tích' : 'Hồ sơ Tình báo Chuyên sâu'}
                </span>
              </div>

              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#fca5a5', marginBottom: '0.75rem' }}>
                {bAi.headline}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.88rem', color: '#e0e7ff', lineHeight: 1.6 }}>
                <div>
                  <strong style={{ color: '#38bdf8' }}>Họ mã độc & Xuất xứ:</strong>
                  <p style={{ margin: '0.2rem 0 0 0' }}>{bAi.threat_family}</p>
                </div>
                <div>
                  <strong style={{ color: '#fbbf24' }}>Ghi nhận từ Cộng đồng Quốc tế trên MalwareBazaar:</strong>
                  <p style={{ margin: '0.2rem 0 0 0' }}>{bAi.bazaar_community_intel}</p>
                </div>
                <div>
                  <strong style={{ color: '#f43f5e' }}>Phân tích Kỹ thuật & Cơ chế hoạt động:</strong>
                  <p style={{ margin: '0.2rem 0 0 0' }}>{bAi.technical_behavior_breakdown}</p>
                </div>
                <div>
                  <strong style={{ color: '#f87171' }}>Nguy cơ đối với Doanh nghiệp & Người dùng Việt Nam:</strong>
                  <p style={{ margin: '0.2rem 0 0 0' }}>{bAi.enterprise_risk}</p>
                </div>
                {bAi.grounding_sources?.length > 0 && (
                  <div>
                    <strong style={{ color: '#10b981' }}>Nguồn xác thực Google Search OSINT:</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.35rem' }}>
                      {bAi.grounding_sources.map((s, idx) => (
                        <a
                          key={idx}
                          href={s.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            padding: '0.2rem 0.55rem',
                            background: '#064e3b',
                            color: '#a7f3d0',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            textDecoration: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                            border: '1px solid #059669',
                          }}
                        >
                          🔗 {s.title || s.url} ↗
                        </a>
                      ))}
                    </div>
                  </div>
                )}
                <div style={{ background: 'rgba(239, 68, 68, 0.15)', padding: '0.6rem 0.8rem', borderRadius: '6px', borderLeft: '3px solid #ef4444' }}>
                  <strong style={{ color: '#fecaca' }}>Khuyến nghị Ứng phó Khẩn cấp:</strong>
                  <p style={{ margin: '0.2rem 0 0 0', whiteSpace: 'pre-line' }}>{bAi.recommended_response}</p>
                </div>
              </div>
            </div>
          )}

          {/* Raw MalwareBazaar Telemetry Card */}
          <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '1.2rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <h4 style={{ margin: 0, fontSize: '0.95rem', color: '#38bdf8' }}>
                Dữ liệu Trích xuất từ MalwareBazaar ({bData?.source || 'MalwareBazaar abuse.ch'})
              </h4>
              <a
                href={bData?.bazaar_url || `https://bazaar.abuse.ch/sample/${sha256}/`}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '0.35rem 0.75rem',
                  background: '#0284c7',
                  color: '#ffffff',
                  borderRadius: '4px',
                  textDecoration: 'none',
                  fontSize: '0.78rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                }}
              >
                Mở trên MalwareBazaar.abuse.ch ↗
              </a>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div>
                <span style={{ color: '#94a3b8' }}>Chữ ký mã độc (Signature):</span>
                <strong style={{ display: 'block', color: sample.signature ? '#f87171' : '#cbd5e1', fontSize: '1rem' }}>
                  {sample.signature || 'Chưa định danh'}
                </strong>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>Người báo cáo (Reporter):</span>
                <strong style={{ display: 'block', color: '#cbd5e1' }}>
                  {sample.reporter || 'Chưa rõ'}
                </strong>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>Thời gian ghi nhận đầu tiên:</span>
                <strong style={{ display: 'block', color: '#cbd5e1' }}>
                  {sample.first_seen || 'N/A'}
                </strong>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>Phương thức phát tán:</span>
                <strong style={{ display: 'block', color: '#cbd5e1' }}>
                  {sample.delivery_method || 'Web / Phishing Email'}
                </strong>
              </div>
            </div>

            {/* Tags */}
            {sample.tags?.length > 0 && (
              <div style={{ marginTop: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', color: '#94a3b8', display: 'block', marginBottom: '0.3rem' }}>Các thẻ phân loại an ninh (Tags):</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                  {sample.tags.map((tag, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: '0.2rem 0.5rem',
                        background: '#1e293b',
                        color: '#38bdf8',
                        borderRadius: '4px',
                        fontSize: '0.78rem',
                        fontWeight: 600,
                        border: '1px solid #334155',
                      }}
                    >
                      #{tag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Hashes breakdown */}
            <div style={{ marginTop: '0.75rem', background: '#0b1120', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><strong>SHA-256:</strong> <code style={{ color: '#38bdf8' }}>{sample.sha256_hash || sha256}</code></div>
              {sample.md5_hash && <div><strong>MD5:</strong> <code>{sample.md5_hash}</code></div>}
              {sample.sha1_hash && <div><strong>SHA-1:</strong> <code>{sample.sha1_hash}</code></div>}
              {sample.imphash && <div><strong>ImpHash:</strong> <code>{sample.imphash}</code></div>}
              {sample.tlsh && <div><strong>TLSH:</strong> <code>{sample.tlsh}</code></div>}
            </div>

            {/* Intelligence / Vendor Intel */}
            {sample.intelligence && Object.keys(sample.intelligence).length > 0 && (
              <div style={{ marginTop: '0.75rem', fontSize: '0.82rem', color: '#94a3b8' }}>
                <strong style={{ color: '#cbd5e1' }}>Quy tắc YARA & Nhận diện Antivirus từ MalwareBazaar:</strong>
                <ul style={{ margin: '0.25rem 0 0 0', paddingLeft: '1.2rem', color: '#cbd5e1' }}>
                  {sample.intelligence.clamav?.map((c, i) => <li key={`c-${i}`}>ClamAV: <code>{c}</code></li>)}
                  {sample.intelligence.yara_rules?.map((y, i) => <li key={`y-${i}`}>YARA Rule: <code>{y}</code></li>)}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Threat Actor */}
      {activeTab === 'actor' && actor && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          <div style={{ background: '#182234', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
            <h4 style={{ margin: '0 0 0.5rem 0', color: '#f87171', fontSize: '0.95rem' }}>Thủ phạm / Nhóm APT</h4>
            <div style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><strong>Tên nhóm:</strong> <span style={{ color: '#fca5a5' }}>{actor.name}</span></div>
              <div><strong>Bí danh (Aliases):</strong> {actor.aliases?.join(', ') || 'N/A'}</div>
              <div><strong>Xuất xứ:</strong> {actor.origin || 'N/A'}</div>
              <div><strong>Phân loại:</strong> {actor.threat_type || 'N/A'}</div>
              <div><strong>Động cơ:</strong> {actor.motivation || 'N/A'}</div>
              <div><strong>Thời gian hoạt động:</strong> {actor.active_period || 'N/A'}</div>
            </div>
          </div>

          <div style={{ background: '#182234', padding: '1rem', borderRadius: '6px', border: '1px solid #334155' }}>
            <h4 style={{ margin: '0 0 0.5rem 0', color: '#38bdf8', fontSize: '0.95rem' }}>Chiến dịch Tấn công</h4>
            <div style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.6 }}>
              <div><strong>Chiến dịch:</strong> <span style={{ color: '#bae6fd' }}>{campaign?.title}</span></div>
              <div><strong>Vector lây nhiễm:</strong> {campaign?.delivery_vector}</div>
              <div><strong>Mã độc chính:</strong> {campaign?.primary_payload}</div>
              <div><strong>Đối tượng mục tiêu:</strong> {campaign?.target_sectors?.join(', ') || 'Doanh nghiệp'}</div>
              <div style={{ marginTop: '0.5rem', color: '#94a3b8', fontStyle: 'italic', fontSize: '0.8rem' }}>
                {campaign?.description}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Attack Chain */}
      {activeTab === 'chain' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {attackChain.map((step) => (
            <div
              key={step.step}
              style={{
                display: 'flex',
                gap: '1rem',
                background: '#182234',
                padding: '0.85rem 1rem',
                borderRadius: '6px',
                borderLeft: '4px solid #f43f5e',
              }}
            >
              <div
                style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '50%',
                  background: '#f43f5e',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: '0.85rem',
                  flexShrink: 0,
                }}
              >
                {step.step}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <strong style={{ color: '#f8fafc', fontSize: '0.9rem' }}>{step.title}</strong>
                  <span style={{ fontSize: '0.75rem', padding: '0.15rem 0.5rem', background: '#334155', color: '#cbd5e1', borderRadius: '4px' }}>
                    {step.phase}
                  </span>
                </div>
                <p style={{ margin: '0.25rem 0 0.5rem 0', color: '#94a3b8', fontSize: '0.85rem', lineHeight: 1.5 }}>
                  {step.detail}
                </p>
                {step.mitre && (
                  <span style={{ fontSize: '0.75rem', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.1)', padding: '0.15rem 0.4rem', borderRadius: '3px' }}>
                    MITRE: {step.mitre}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 4: MITRE ATT&CK */}
      {activeTab === 'mitre' && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem', color: '#cbd5e1' }}>
            <thead>
              <tr style={{ background: '#1e293b', textAlign: 'left' }}>
                <th style={{ padding: '0.6rem 0.75rem' }}>Mã MITRE</th>
                <th style={{ padding: '0.6rem 0.75rem' }}>Kỹ thuật Tấn công</th>
                <th style={{ padding: '0.6rem 0.75rem' }}>Chiến thuật (Tactic)</th>
                <th style={{ padding: '0.6rem 0.75rem' }}>Mức độ Nguy cơ</th>
              </tr>
            </thead>
            <tbody>
              {mitreMatrix.map((m, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.6rem 0.75rem' }}>
                    <a
                      href={`https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#38bdf8', textDecoration: 'none', fontWeight: 600 }}
                    >
                      {m.id}
                    </a>
                  </td>
                  <td style={{ padding: '0.6rem 0.75rem', color: '#f8fafc' }}>{m.name}</td>
                  <td style={{ padding: '0.6rem 0.75rem', color: '#94a3b8' }}>{m.tactic}</td>
                  <td style={{ padding: '0.6rem 0.75rem' }}>
                    <span
                      style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        background: m.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                        color: m.severity === 'CRITICAL' ? '#f87171' : '#fbbf24',
                      }}
                    >
                      {m.severity}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TAB 5: Databases */}
      {activeTab === 'databases' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {databases.map((db, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: '#182234',
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                border: '1px solid #334155',
                flexWrap: 'wrap',
                gap: '0.5rem',
              }}
            >
              <div>
                <strong style={{ color: '#f8fafc', fontSize: '0.9rem' }}>{db.database}</strong>
                <p style={{ margin: '0.15rem 0 0 0', color: '#94a3b8', fontSize: '0.8rem' }}>{db.type}</p>
                <small style={{ color: '#64748b' }}>Trạng thái: {db.status}</small>
              </div>
              <a
                href={db.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '0.4rem 0.8rem',
                  background: '#0284c7',
                  color: '#ffffff',
                  borderRadius: '4px',
                  textDecoration: 'none',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem',
                }}
              >
                Mở tra cứu ↗
              </a>
            </div>
          ))}
        </div>
      )}

      {/* TAB 6: Google Search Grounding OSINT */}
      {activeTab === 'google' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {googleData ? (
            <div style={{ background: '#064e3b', border: '1px solid #059669', borderRadius: '8px', padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#a7f3d0', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>🌐 Kết quả Tra cứu Google Search OSINT (Gemini 2.5 Flash Grounding)</span>
                </h3>
                <span style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem', background: '#047857', color: '#ecfdf5', borderRadius: '4px' }}>
                  {googleData.is_ai_grounded ? '✨ Real-time Grounded' : 'Kết quả mặc định'}
                </span>
              </div>

              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#fef08a', marginBottom: '0.75rem' }}>
                {googleData.headline}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.88rem', color: '#ecfdf5', lineHeight: 1.6 }}>
                <div>
                  <strong style={{ color: '#6ee7b7' }}>Dòng mã độc / Nhận diện:</strong>
                  <p style={{ margin: '0.2rem 0 0 0', fontWeight: 600, color: '#fef08a' }}>{googleData.threat_family}</p>
                </div>

                {googleData.detection_sources?.length > 0 && (
                  <div>
                    <strong style={{ color: '#6ee7b7' }}>Các hãng / Nguồn an ninh mạng đã ghi nhận:</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.25rem' }}>
                      {googleData.detection_sources.map((src, idx) => (
                        <span key={idx} style={{ padding: '0.2rem 0.5rem', background: '#065f46', borderRadius: '4px', fontSize: '0.75rem', color: '#d1fae5', border: '1px solid #10b981' }}>
                          🛡️ {src}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <strong style={{ color: '#6ee7b7' }}>Cơ chế hoạt động & Hành vi phá hoại:</strong>
                  <p style={{ margin: '0.2rem 0 0 0', whiteSpace: 'pre-line' }}>{googleData.technical_behavior}</p>
                </div>

                <div>
                  <strong style={{ color: '#fca5a5' }}>Nguy cơ đối với Doanh nghiệp & Hệ thống:</strong>
                  <p style={{ margin: '0.2rem 0 0 0' }}>{googleData.enterprise_risk}</p>
                </div>

                <div style={{ background: 'rgba(239, 68, 68, 0.25)', padding: '0.6rem 0.8rem', borderRadius: '6px', borderLeft: '3px solid #ef4444' }}>
                  <strong style={{ color: '#fecaca' }}>Khuyến nghị Ứng phó Khẩn cấp:</strong>
                  <p style={{ margin: '0.2rem 0 0 0', whiteSpace: 'pre-line' }}>{googleData.recommended_response}</p>
                </div>

                {googleData.sources?.length > 0 && (
                  <div>
                    <strong style={{ color: '#6ee7b7' }}>Nguồn tham chiếu gốc (Google Grounding Sources):</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.3rem' }}>
                      {googleData.sources.map((s, idx) => (
                        <a
                          key={idx}
                          href={s.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            padding: '0.25rem 0.55rem',
                            background: '#047857',
                            color: '#ffffff',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            textDecoration: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                            border: '1px solid #34d399',
                          }}
                        >
                          🔗 {s.title || s.url} ↗
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {googleData.search_queries?.length > 0 && (
                  <div>
                    <strong style={{ color: '#94a3b8', fontSize: '0.78rem' }}>Truy vấn tìm kiếm đã thực hiện:</strong>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', marginTop: '0.2rem' }}>
                      {googleData.search_queries.map((q, idx) => (
                        <span key={idx} style={{ padding: '0.15rem 0.4rem', background: '#022c22', borderRadius: '3px', fontSize: '0.72rem', color: '#6ee7b7' }}>
                          🔍 {q}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem', background: '#0f172a', borderRadius: '8px', border: '1px dashed #334155' }}>
              <p style={{ color: '#94a3b8', marginBottom: '1rem' }}>
                Chưa có dữ liệu tra cứu Google Search OSINT. Nhấn nút bên dưới để tìm kiếm thông tin về mã băm này trên các nguồn tình báo toàn cầu.
              </p>
              <button
                type="button"
                onClick={handleGoogleSearch}
                disabled={googleLoading}
                style={{
                  padding: '0.6rem 1.2rem',
                  background: '#059669',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  fontSize: '0.9rem',
                  fontWeight: 600,
                  cursor: googleLoading ? 'not-allowed' : 'pointer',
                }}
              >
                {googleLoading ? '⏳ Đang tra cứu trên Google…' : '🌐 Bắt đầu Tra cứu Google Search OSINT'}
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
