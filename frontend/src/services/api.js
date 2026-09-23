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
