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
  ['total_scans', 'Tổng lượt quét'],
  ['url_scans', 'Quét URL'],
  ['file_scans', 'Quét tệp'],
  ['safe_results', 'Kết quả an toàn'],
  ['high_risk_results', 'Rủi ro cao'],
  ['critical_results', 'Nghiêm trọng'],
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
        setError(requestError.message || 'Không thể tải trang tổng quan.')
      })
  }, [])

  return (
    <section className="dashboard-page">
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">Không gian bảo mật</p>
          <h1>Tổng quan</h1>
          <p className="lead">Theo dõi các lượt quét phishing và tệp PE tĩnh.</p>
        </div>
        <div className="api-indicator"><span className={`status-dot ${apiStatus}`} />API: {apiStatus === 'ok' ? 'Hoạt động' : apiStatus === 'offline' ? 'Ngoại tuyến' : 'Đang kiểm tra'}</div>
      </div>

      {error && <div className="scanner-error" role="alert">{error}</div>}
      {!data && !error && <div className="loading-panel">Đang tải dữ liệu tổng quan…</div>}

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
              <h2>Số lượt quét theo thời gian</h2>
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
              <h2>Phân bố mức rủi ro</h2>
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
              <h2>Phishing và mã độc</h2>
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
              <h2>Phân bố dự đoán</h2>
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
            <div className="card-heading"><h2>Lượt quét gần đây</h2><span>{data.recent_scans.length} mới nhất</span></div>
            <ScanTable scans={data.recent_scans} emptyMessage="Hãy thực hiện quét phishing hoặc mã độc để hiển thị dữ liệu." />
          </article>
        </>
      )}
    </section>
  )
}
