const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

async function parseResponse(response) {
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message = typeof data.detail === 'string' ? data.detail : `Request failed with status ${response.status}`
    throw new Error(message)
  }
  return data
}

export async function getHealth() {
  const response = await fetch(`${API_BASE_URL}/health`)
  return parseResponse(response)
}

export async function analyzePhishingUrl(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function analyzePhishingHtml(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/html-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function analyzePhishingJavascript(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/javascript-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function analyzePhishingSandbox(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/sandbox-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function analyzePhishingVisual(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/visual-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function analyzePhishingDownloads(url) {
  const response = await fetch(`${API_BASE_URL}/phishing/download-analysis`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  return parseResponse(response)
}

export async function lookupThreatIntelligence(indicatorType, value) {
  const response = await fetch(`${API_BASE_URL.replace('/api', '')}/api/threat-intelligence/lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ indicator_type: indicatorType, value }),
  })
  return parseResponse(response)
}

export async function analyzeMalwareFile(file) {
  const formData = new FormData()
  formData.append('file', file)
  const response = await fetch(`${API_BASE_URL}/malware/analyze`, {
    method: 'POST',
    body: formData,
  })
  return parseResponse(response)
}

export async function getDashboard() {
  const response = await fetch(`${API_BASE_URL}/dashboard`)
  return parseResponse(response)
}

export async function getScanHistory(filters = {}, signal) {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== '' && value !== null && value !== undefined) params.set(key, value)
  })
  const response = await fetch(`${API_BASE_URL}/history?${params.toString()}`, { signal })
  return parseResponse(response)
}

export async function getModelMetrics() {
  const response = await fetch(`${API_BASE_URL}/metrics`)
  return parseResponse(response)
}

export async function getModelMetricsByType(type) {
  const response = await fetch(`${API_BASE_URL}/metrics/${type}`)
  return parseResponse(response)
}

export async function getFriendlyAIExplanation(scanData, apiKey = null) {
  const response = await fetch(`${API_BASE_URL}/phishing/ai-explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_data: scanData, api_key: apiKey }),
  })
  return parseResponse(response)
}

export async function detonateMalwareSandbox(payload) {
  const response = await fetch(`${API_BASE_URL}/malware/sandbox-detonation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  return parseResponse(response)
}

export async function lookupMalwareBazaar(sha256, filename = '', geminiApiKey = null, bazaarApiKey = null) {
  const response = await fetch(`${API_BASE_URL}/malware/bazaar-lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sha256,
      filename,
      gemini_api_key: geminiApiKey,
      bazaar_api_key: bazaarApiKey,
    }),
  })
  return parseResponse(response)
}

export async function searchGoogleThreatIntel(sha256, filename = '', geminiApiKey = null) {
  const response = await fetch(`${API_BASE_URL}/malware/google-threat-lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sha256,
      filename,
      gemini_api_key: geminiApiKey,
    }),
  })
  return parseResponse(response)
}

