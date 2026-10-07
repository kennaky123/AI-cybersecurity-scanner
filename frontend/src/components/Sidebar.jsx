const navigation = [
  { id: 'dashboard', label: 'Tổng quan', icon: '⌂', hotkey: '1' },
  { id: 'phishing', label: 'Quét phishing', icon: '⌁', hotkey: '2' },
  { id: 'malware', label: 'Quét mã độc', icon: '◈', hotkey: '3' },
  { id: 'history', label: 'Lịch sử quét', icon: '↻', hotkey: '4' },
  { id: 'metrics', label: 'Vì sao dùng app này?', icon: '▥', hotkey: '5' },
]

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">AI</span>
        <div>
          <strong>Cybersecurity</strong>
          <span>Workbench v2.0</span>
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
            <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span aria-hidden="true">{item.icon}</span>
              {item.label}
            </span>
            <kbd className="nav-hotkey">{item.hotkey}</kbd>
          </button>
        ))}
      </nav>
      
      <div className="phase-badge">
        <span>Giai đoạn 10 · AI có giải thích</span>
        <span className="phase-dot" title="Hệ thống hoạt động" />
      </div>
    </aside>
  )
}
