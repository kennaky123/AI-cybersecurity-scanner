import { lazy, Suspense, useEffect, useState } from 'react'
import Navbar from './components/Navbar.jsx'

const Dashboard = lazy(() => import('./pages/Dashboard.jsx'))
const MalwareScanner = lazy(() => import('./pages/MalwareScanner.jsx'))
const ModelMetrics = lazy(() => import('./pages/ModelMetrics.jsx'))
const PhishingScanner = lazy(() => import('./pages/PhishingScanner.jsx'))
const ScanHistory = lazy(() => import('./pages/ScanHistory.jsx'))

const pages = {
  dashboard: Dashboard,
  phishing: PhishingScanner,
  malware: MalwareScanner,
  history: ScanHistory,
  metrics: ModelMetrics,
}

const pageOrder = ['dashboard', 'phishing', 'malware', 'history', 'metrics']

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const ActivePage = pages[activePage]

  useEffect(() => {
    function handleKeyDown(event) {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target.tagName)) {
        return
      }
      const keyNumber = parseInt(event.key, 10)
      if (keyNumber >= 1 && keyNumber <= 5) {
        const targetPage = pageOrder[keyNumber - 1]
        if (targetPage) {
          setActivePage(targetPage)
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  return (
    <div className="app-layout">
      <Navbar activePage={activePage} onNavigate={setActivePage} />
      <main className="main-canvas">
        <Suspense fallback={<div className="loading-panel">Đang chuẩn bị không gian làm việc…</div>}>
          <ActivePage />
        </Suspense>
      </main>
      <footer className="app-footer">
        <div className="footer-container">
          <span>Hệ thống Kiểm tra & Triage An ninh mạng bằng Trí tuệ nhân tạo (AI Cybersecurity)</span>
          <span className="footer-badge">Giai đoạn 10: XAI Ngoại tuyến · Defense-in-Depth</span>
        </div>
      </footer>
    </div>
  )
}
