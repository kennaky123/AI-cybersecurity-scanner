const navigation = [
  { id: 'dashboard', label: 'Dashboard', icon: '⌂' },
  { id: 'phishing', label: 'Phishing Scanner', icon: '⌁' },
  { id: 'malware', label: 'Malware Scanner', icon: '◈' },
  { id: 'history', label: 'Scan History', icon: '↻' },
  { id: 'metrics', label: 'Model Metrics', icon: '▥' },
]

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">AI</span>
        <div>
          <strong>Cybersecurity</strong>
          <span>Scanner</span>
        </div>
      </div>
      <nav aria-label="Điều hướng chính">
        {navigation.map((item) => (
          <button
            className={activePage === item.id ? 'nav-item active' : 'nav-item'}
            key={item.id}
            onClick={() => onNavigate(item.id)}
            type="button"
          >
            <span aria-hidden="true">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>
      <p className="phase-badge">Phase 10 · Explainable AI</p>
    </aside>
  )
}
