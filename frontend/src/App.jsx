import { lazy, Suspense, useState } from 'react'
import Sidebar from './components/Sidebar.jsx'

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

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')
  const ActivePage = pages[activePage]

  return (
    <div className="app-shell">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />
      <main className="main-content">
        <Suspense fallback={<div className="loading-panel">Loading page…</div>}>
          <ActivePage />
        </Suspense>
      </main>
    </div>
  )
}
