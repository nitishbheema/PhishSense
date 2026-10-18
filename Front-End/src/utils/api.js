// PhishSense API utility — communicates with Spring Boot backend (port 8080)
// and AI service (port 8000) where needed.

const BASE     = import.meta.env.VITE_API_URL     || 'http://localhost:8080'
const AI_BASE  = import.meta.env.VITE_AI_URL      || 'http://localhost:8000'

// ── Generic helpers ───────────────────────────────────────────────────────────
function getAuthHeaders() {
  const token = localStorage.getItem('phishsense_token')
  const headers = { 'Content-Type': 'application/json' }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

async function get(path, base = BASE) {
  try {
    const r = await fetch(`${base}${path}`, {
      headers: getAuthHeaders(),
    })
    if (!r.ok) {
      if (r.status === 401) {
        // Token might have expired
        window.dispatchEvent(new CustomEvent('phishsense:unauthorized'))
      }
      throw new Error(r.status)
    }
    return await r.json()
  } catch { return null }
}

async function post(path, body, base = BASE) {
  try {
    const r = await fetch(`${base}${path}`, {
      method:  'POST',
      headers: getAuthHeaders(),
      body:    JSON.stringify(body),
    })
    const data = await r.json()
    if (!r.ok) {
      if (r.status === 401) {
        window.dispatchEvent(new CustomEvent('phishsense:unauthorized'))
      }
      // Always return the error from the server so UI can show it
      return { error: data?.error || `Server error (${r.status})` }
    }
    return data
  } catch (e) {
    console.warn('[PhishSense API] request error:', e.message)
    if (e.message && !e.message.startsWith('HTTP') && !e.message.includes('fetch') && !e.message.includes('Failed to fetch')) {
      return { error: e.message }
    }
    return { error: 'Unable to reach server. Please check if the backend is running.' }
  }
}


// ── Behavioral analysis ───────────────────────────────────────────────────────
export async function analyzeBehavior(session) {
  const result = await post('/api/behavior/analyze', session)
  if (result) return result
  const s = session.anomalyScore || 0
  return {
    sessionId: session.sessionId,
    label: s >= 65 ? 'PHISHING' : s >= 35 ? 'SUSPICIOUS' : 'LEGIT',
    threatScore: s, confidence: 0.70, flags: session.flags || [],
    loggedToBlockchain: false, blockHash: null,
    message: 'Backend offline — local heuristic used',
  }
}

// ── Unified URL scan ──────────────────────────────────────────────────────────
export async function scanUrl(url, behaviorFeatures = null) {
  const body = { url }
  if (behaviorFeatures) body.behavior = behaviorFeatures

  const result = await post('/api/scan', body)
  if (result) return result

  // Local heuristic fallback
  const lower = url.toLowerCase()
  const suspiciousTLDs = ['.click', '.info', '.xyz', '.top', '.tk', '.cf', '.ml']
  let score = 0
  if (suspiciousTLDs.some(t => lower.includes(t))) score += 30
  if (lower.includes('@'))                          score += 20
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower)) score += 30
  if (lower.includes('login') && lower.includes('secure')) score += 15

  const label = score >= 60 ? 'PHISHING' : score >= 30 ? 'SUSPICIOUS' : 'LEGIT'
  return {
    url, label, threat_score: score, confidence: 0.5, input_type: 'URL',
    threat_category: 'General Web Services',
    attack_family: 'Threat Family #1 (Credential Harvesting Portal)',
    similarity_analysis: { related_threat_found: false, similarity_score: 0.0 },
    risk_breakdown: { url_risk: score, webpage_risk: 0, behavior_risk: 0, ai_deception_score: 0, threat_intel_score: 0 },
    threat_intelligence: { fingerprint: null, previously_detected: false, prior_detection_count: 0 },
    flags: [], explainability: [], logged_to_blockchain: false, block_hash: null,
    source: 'PhishSense (Heuristic — Backend offline)',
    timestamp: new Date().toISOString(),
  }
}

// ── QR code scan ─────────────────────────────────────────────────────────────
export async function scanQr(decodedUrl, rawData = '') {
  const result = await post('/api/scan/qr', { decoded_url: decodedUrl, raw_data: rawData })
  if (result) return result
  return await scanUrl(decodedUrl)
}

// ── Website analysis ─────────────────────────────────────────────────────────
export async function analyzeWebsite(url) {
  const result = await post('/api/scan/website', { url })
  if (result) return result
  return await scanUrl(url)
}

// ── User Feedback Loop (Section 20) ───────────────────────────────────────────
export async function submitFeedback(payload) {
  return post('/api/feedback', payload)
}

export const getFeedbackStats = () => get('/api/feedback/stats')

// ── Threat intelligence & History ─────────────────────────────────────────────
export async function getUrlHistory(url) {
  return get(`/api/scan/history?url=${encodeURIComponent(url)}`)
}

export async function lookupFingerprint(fingerprint) {
  return get(`/api/scan/fingerprint/${fingerprint}`)
}

export async function getFilteredHistory(params = {}) {
  const q = new URLSearchParams()
  if (params.inputType)  q.set('inputType', params.inputType)
  if (params.threatType) q.set('threatType', params.threatType)
  if (params.minScore)   q.set('minScore', params.minScore)
  if (params.maxScore)   q.set('maxScore', params.maxScore)
  if (params.search)     q.set('search', params.search)
  return get(`/api/scan/history/filter?${q.toString()}`)
}

export const getAttackFamilies = () => get('/api/threats/families')

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const getDashboardStats  = () => get('/api/behavior/stats')
export const getRecentSessions  = () => get('/api/behavior/recent')
export const getRecentThreats   = () => get('/api/threats/recent')
export const getBlockchain      = () => get('/api/blockchain/chain')
export const validateChain      = () => get('/api/blockchain/validate')
export const getMempool         = () => get('/api/blockchain/mempool')

// ── Research & Model Info ─────────────────────────────────────────────────────
export const getModelInfo           = () => get('/model/info', AI_BASE)
export const getResearchMetrics     = () => get('/research/metrics', AI_BASE)
export const getResearchExperiments = () => get('/research/experiments', AI_BASE)
export const getResearchEvasion     = () => get('/research/evasion', AI_BASE)

// ── Single-User Authentication & Profile & Alerts ─────────────────────────────
export const loginWithEmail      = (email) => post('/api/auth/email', { email })
export const requestOtp          = (email) => post('/api/auth/otp/request', { email })
export const verifyOtp           = (email, otp) => post('/api/auth/otp/verify', { email, otp })
export const loginWithGoogle     = (payload) => post('/api/auth/google', payload)
export const getMe               = () => get('/api/auth/me')
export const logoutUser          = () => post('/api/auth/logout', {})

export const getUserProfile      = () => get('/api/user/profile')
export const getUserScans        = () => get('/api/user/scans')
export const getUserAlerts       = () => get('/api/user/alerts')
export const acknowledgeAlert    = (id) => post(`/api/user/alerts/${id}/ack`, {})
export const acknowledgeAllAlerts = () => post('/api/user/alerts/ack-all', {})
