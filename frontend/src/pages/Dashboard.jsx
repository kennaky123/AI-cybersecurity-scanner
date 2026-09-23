import { useEffect, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import ScanTable from '../components/ScanTable.jsx'
import { getDashboard, getHealth } from '../services/api.js'

const RISK_COLORS = ['#34d399', '#fbbf24', '#fb923c', '#fb7185']
const TYPE_COLORS = ['#22d3ee', '#a78bfa']

const summaryCards = [
  ['total_scans', 'Total scans'],
  ['url_scans', 'URL scans'],
  ['file_scans', 'File scans'],
  ['safe_results', 'Safe results'],
  ['high_risk_results', 'High risk'],
  ['critical_results', 'Critical'],
]

export default function Dashboard() {
  const [apiStatus, setApiStatus] = useState('checking')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    Promise.all([getHealth(), getDashboard()])
      .then(([health, dashboard]) => {
        setApiStatus(health.status)
        setData(dashboard)
      })
      .catch((requestError) => {
        setApiStatus('offline')
        setError(requestError.message || 'Unable to load dashboard.')
      })
  }, [])

  return (
    <section className="dashboard-page">
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">Security workspace</p>
          <h1>Dashboard</h1>
          <p className="lead">Operational view of phishing and static PE scans.</p>
        </div>
        <div className="api-indicator"><span className={`status-dot ${apiStatus}`} />API {apiStatus}</div>
      </div>

      {error && <div className="scanner-error" role="alert">{error}</div>}
      {!data && !error && <div className="loading-panel">Loading dashboard…</div>}

      {data && (
        <>
          <div className="summary-grid">
            {summaryCards.map(([key, label]) => (
              <article key={key} className={`summary-card ${key}`}>
                <span>{label}</span>
                <strong>{data.summary[key]}</strong>
              </article>
            ))}
          </div>

          <div className="chart-grid">
            <article className="chart-card chart-wide">
              <h2>Scan count over time</h2>
              <ResponsiveContainer width="100%" height={270}>
                <AreaChart data={data.scan_count_over_time}>
                  <defs>
                    <linearGradient id="scanGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#17344e" strokeDasharray="3 3" />
                  <XAxis dataKey="date" stroke="#7892b2" tick={{ fontSize: 12 }} />
                  <YAxis allowDecimals={false} stroke="#7892b2" tick={{ fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#091625', border: '1px solid #24506f' }} />
                  <Area type="monotone" dataKey="total" stroke="#22d3ee" fill="url(#scanGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </article>

            <article className="chart-card">
              <h2>Risk distribution</h2>
              <ResponsiveContainer width="100%" height={270}>
                <PieChart>
                  <Pie data={data.risk_distribution} dataKey="value" nameKey="name" innerRadius={55} outerRadius={88} paddingAngle={3}>
                    {data.risk_distribution.map((entry, index) => <Cell key={entry.name} fill={RISK_COLORS[index]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#091625', border: '1px solid #24506f' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </article>

            <article className="chart-card">
              <h2>Phishing vs Malware</h2>
              <ResponsiveContainer width="100%" height={270}>
                <PieChart>
                  <Pie data={data.scan_type_distribution} dataKey="value" nameKey="name" outerRadius={88} label>
                    {data.scan_type_distribution.map((entry, index) => <Cell key={entry.name} fill={TYPE_COLORS[index]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#091625', border: '1px solid #24506f' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </article>

            <article className="chart-card chart-wide">
              <h2>Prediction distribution</h2>
              <ResponsiveContainer width="100%" height={270}>
                <BarChart data={data.prediction_distribution}>
                  <CartesianGrid stroke="#17344e" strokeDasharray="3 3" />
                  <XAxis dataKey="name" stroke="#7892b2" tick={{ fontSize: 12 }} />
                  <YAxis allowDecimals={false} stroke="#7892b2" tick={{ fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#091625', border: '1px solid #24506f' }} />
                  <Bar dataKey="value" fill="#a78bfa" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </article>
          </div>

          <article className="history-card">
            <div className="card-heading"><h2>Recent scans</h2><span>{data.recent_scans.length} latest</span></div>
            <ScanTable scans={data.recent_scans} emptyMessage="Run a phishing or malware scan to populate the dashboard." />
          </article>
        </>
      )}
    </section>
  )
}
