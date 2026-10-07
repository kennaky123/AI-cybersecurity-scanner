import { useEffect, useState } from 'react'
import { getHealth } from '../services/api.js'

const navItems = [
  { id: 'dashboard', label: 'Tổng quan', icon: '⌂', hotkey: '1' },
  { id: 'phishing', label: 'Quét Phishing', icon: '⌁', hotkey: '2' },
  { id: 'malware', label: 'Quét Mã độc', icon: '◈', hotkey: '3' },
  { id: 'history', label: 'Lịch sử quét', icon: '↻', hotkey: '4' },
  { id: 'metrics', label: 'Đo lường & So sánh', icon: '▥', hotkey: '5' },
]

export default function Navbar({ activePage, onNavigate }) {
  const [apiStatus, setApiStatus] = useState('checking')

  useEffect(() => {
    getHealth()
      .then((res) => setApiStatus(res.status))
      .catch(() => setApiStatus('offline'))
  }, [])

  return (
    <header className="top-navbar">
      <div className="navbar-container">
        {/* Brand Logo */}
        <div className="navbar-brand" onClick={() => onNavigate('dashboard')} role="button" tabIndex={0}>
          <div className="brand-icon-box">
            <span>🛡️</span>
          </div>
          <div className="brand-text">
            <div className="brand-title">
              CYBER<strong>SHIELD</strong>
              <span className="brand-tag">AI</span>
            </div>
            <span className="brand-subtitle">An ninh mạng & Phân tích tĩnh</span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="navbar-tabs" aria-label="Điều hướng chính">
          {navItems.map((item) => {
            const isActive = activePage === item.id
            return (
              <button
                key={item.id}
                type="button"
                className={`navbar-tab-btn ${isActive ? 'active' : ''}`}
                onClick={() => onNavigate(item.id)}
              >
                <span className="tab-icon">{item.icon}</span>
                <span className="tab-label">{item.label}</span>
                <kbd className="tab-hotkey">{item.hotkey}</kbd>
              </button>
            )
          })}
        </nav>

        {/* System Telemetry & Status */}
        <div className="navbar-status-wrap">
          <div className={`status-pill ${apiStatus === 'ok' ? 'live' : apiStatus === 'offline' ? 'offline' : 'checking'}`}>
            <span className="status-ping-dot" />
            <span>{apiStatus === 'ok' ? 'Hệ thống Sẵn sàng' : apiStatus === 'offline' ? 'Mất kết nối API' : 'Đang kiểm tra'}</span>
          </div>
        </div>
      </div>
    </header>
  )
}
