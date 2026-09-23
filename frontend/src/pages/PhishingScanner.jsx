import { useState } from 'react'
import ExplanationPanel from '../components/ExplanationPanel.jsx'
import { analyzePhishingUrl } from '../services/api.js'

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

function featureLabel(name) {
  return name.replaceAll('_', ' ').replace(/^./, (character) => character.toUpperCase())
}

export default function PhishingScanner() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      setResult(await analyzePhishingUrl(url.trim()))
    } catch (requestError) {
      setError(requestError.message || 'Unable to analyze this URL.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="scanner-page">
      <p className="eyebrow">ML-powered URL analysis</p>
      <h1>Phishing Scanner</h1>
      <p className="lead">Analyze lexical URL signals with the trained phishing model. The scanner never visits the submitted website.</p>

      <form className="scanner-form" onSubmit={handleSubmit}>
        <label htmlFor="phishing-url">URL to analyze</label>
        <div className="input-row">
          <input
            id="phishing-url"
            type="url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com"
            autoComplete="url"
            required
            disabled={loading}
          />
          <button type="submit" disabled={loading || !url.trim()}>
            {loading ? 'Analyzing…' : 'Scan URL'}
          </button>
        </div>
      </form>

      {error && <div className="scanner-error" role="alert">{error}</div>}

      {result && (
        <div className="scan-result" aria-live="polite">
          <div className="result-heading">
            <div>
              <span>Prediction</span>
              <strong className={result.prediction === 'PHISHING' ? 'danger' : 'safe'}>{result.prediction}</strong>
            </div>
            <span className={`risk-pill ${result.risk_level.toLowerCase()}`}>{result.risk_level}</span>
          </div>

          <div className="metric-grid">
            <article>
              <span>Risk score</span>
              <strong>{result.risk_score}<small>/100</small></strong>
            </article>
            <article>
              <span>Phishing probability</span>
              <strong>{(result.probability * 100).toFixed(2)}<small>%</small></strong>
            </article>
            <article>
              <span>Risk level</span>
              <strong>{result.risk_level}</strong>
            </article>
          </div>

          <div className="result-section">
            <h2>Important URL features</h2>
            <div className="feature-grid">
              {importantFeatures.map((name) => (
                <div key={name}>
                  <span>{featureLabel(name)}</span>
                  <code>{result.features[name]}</code>
                </div>
              ))}
            </div>
          </div>

          <ExplanationPanel explanation={result.explanation} riskLabel="phishing" />
        </div>
      )}
    </section>
  )
}
