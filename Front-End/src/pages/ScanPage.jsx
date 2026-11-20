import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Shield, ScanLine, QrCode, Globe, AlertTriangle, CheckCircle2,
  XCircle, Link2, Activity, ChevronRight, Upload, Camera, Loader2,
  Info, Eye, Lock, Cpu, Database, TrendingUp, ThumbsUp, ThumbsDown,
  ExternalLink, ArrowLeft, Layers, Check, X, ShieldAlert, CornerDownRight,
  Fingerprint, Copy, ShieldCheck, RefreshCw, AlertCircle
} from 'lucide-react'
import jsQR from 'jsqr'
import { scanUrl, scanQr, analyzeWebsite, auditWebsite, verifyDomainOwnership, submitFeedback } from '../utils/api'
import { useAuth } from '../context/AuthContext'
import WebsiteAuditReport from '../components/WebsiteAuditReport'

// ── Constants ─────────────────────────────────────────────────────────────────
const TABS = [
  { key: 'url',   label: 'Quick Link Check',      icon: ScanLine },
  { key: 'qr',    label: 'Decode QR Code',        icon: QrCode },
  { key: 'audit', label: 'Website Security Audit', icon: Globe },
]

const PRESET_SAMPLES = [
  { label: 'SBI KYC Update Scam (SMS)', url: 'http://sbi-kyc-pan-update.com/login', tag: 'Phishing' },
  { label: 'India Post Delivery Fraud', url: 'http://indiapost-parce1-redelivery.in/track', tag: 'Phishing' },
  { label: 'Electricity Bill Notice', url: 'http://bijli-bill-payment-alert.xyz/pay', tag: 'Phishing' },
  { label: 'Official State Bank of India', url: 'https://onlinesbi.sbi', tag: 'Safe' },
  { label: 'Official India Post Portal', url: 'https://www.indiapost.gov.in', tag: 'Safe' },
]

const AUDIT_PRESETS = [
  { label: 'WordPress CMS Audit', url: 'https://wordpress.org' },
  { label: 'Enterprise Reference (GitHub)', url: 'https://github.com' },
  { label: 'API & Headers Sandbox', url: 'https://httpbin.org' },
]

const RISK_CONFIG = {
  PHISHING: {
    color: '#e11d48',
    bg: '#fff1f2',
    border: '#fecdd3',
    label: 'Phishing Scam',
    badgeBg: '#ffe4e6',
    badgeText: '#be123c',
    summary: 'High danger. This destination mimics authentic services or is flagged in verified threat databases.',
    actionAdvice: 'Do not click or submit any personal information, OTP, or passwords. Delete or close the message immediately.',
  },
  SUSPICIOUS: {
    color: '#d97706',
    bg: '#fffbeb',
    border: '#fde68a',
    label: 'Suspicious Link',
    badgeBg: '#fef3c7',
    badgeText: '#b45309',
    summary: 'Anomalous structural patterns detected (e.g., lookalike brand domain, unusual redirect hop, or unverified host).',
    actionAdvice: 'Exercise extreme caution. Do not enter passwords, phone numbers, or authorize payments on this site.',
  },
  INSUFFICIENT_EVIDENCE: {
    color: '#64748b',
    bg: '#f8fafc',
    border: '#cbd5e1',
    label: 'Insufficient Evidence',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    summary: 'The target host is unreachable, DNS failed to resolve, or remote connection timed out. Absence of data is not proof of safety.',
    actionAdvice: 'Do not trust this link blindly. Confirm with the authentic organization through official customer support.',
  },
  UNVERIFIED: {
    color: '#64748b',
    bg: '#f8fafc',
    border: '#cbd5e1',
    label: 'Insufficient Evidence',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    summary: 'The target host is unreachable, DNS failed to resolve, or remote connection timed out. Absence of data is not proof of safety.',
    actionAdvice: 'Do not trust this link blindly. Confirm with the authentic organization through official customer support.',
  },
  ANALYSIS_FAILED: {
    color: '#dc2626',
    bg: '#fef2f2',
    border: '#fecaca',
    label: 'Analysis Incomplete',
    badgeBg: '#fee2e2',
    badgeText: '#991b1b',
    summary: 'Scan analysis could not complete due to temporary service unavailability. Unverified links must not be assumed safe.',
    actionAdvice: 'Please retry the scan in a moment. Never open unverified links sent via SMS or messaging apps.',
  },
  RATE_LIMITED: {
    color: '#d97706',
    bg: '#fffbeb',
    border: '#fde68a',
    label: 'Rate Limit Reached',
    badgeBg: '#fef3c7',
    badgeText: '#b45309',
    summary: 'You have submitted too many scan requests in a short time window. Please wait a moment before trying again.',
    actionAdvice: 'Wait a few minutes to protect system availability for all users.',
  },
  LEGITIMATE: {
    color: '#059669',
    bg: '#f0fdf4',
    border: '#bbf7d0',
    label: 'Clean & Verified',
    badgeBg: '#dcfce7',
    badgeText: '#047857',
    summary: 'Recognized legitimate domain structure with clean threat database records and authentic brand identity.',
    actionAdvice: 'Safe to proceed. Standard browsing precautions apply.',
  },
  LEGIT: {
    color: '#059669',
    bg: '#f0fdf4',
    border: '#bbf7d0',
    label: 'Clean & Verified',
    badgeBg: '#dcfce7',
    badgeText: '#047857',
    summary: 'Recognized legitimate domain structure with clean threat database records and authentic brand identity.',
    actionAdvice: 'Safe to proceed. Standard browsing precautions apply.',
  },
}

function getRiskConfig(label, internalState) {
  if (internalState === 'INSUFFICIENT_EVIDENCE') return RISK_CONFIG.INSUFFICIENT_EVIDENCE
  if (internalState === 'ANALYSIS_FAILED') return RISK_CONFIG.ANALYSIS_FAILED
  if (internalState === 'RATE_LIMITED') return RISK_CONFIG.RATE_LIMITED
  const key = (label || '').toUpperCase()
  return RISK_CONFIG[key] || (key.includes('PHISH') ? RISK_CONFIG.PHISHING : key.includes('LEGIT') ? RISK_CONFIG.LEGITIMATE : RISK_CONFIG.SUSPICIOUS)
}

function RiskBar({ value, color, label }) {
  const pct = Math.min(100, Math.max(0, value))
  const c = value > 65 ? '#e11d48' : value > 35 ? '#d97706' : '#059669'
  return (
    <div className="mb-3">
      <div className="flex justify-between items-center text-xs mb-1">
        <span className="text-slate-600 font-medium">{label}</span>
        <span className="font-semibold font-mono" style={{ color: color || c }}>{value}%</span>
      </div>
      <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200">
        <div
          className="h-full rounded-full transition-all duration-500 ease-out"
          style={{ width: `${pct}%`, background: color || c }}
        />
      </div>
    </div>
  )
}

function ScoreRing({ score, label, internalState }) {
  const cfg = getRiskConfig(label, internalState)
  const circumference = 2 * Math.PI * 45
  const strokeDashoffset = circumference - (score / 100) * circumference
  return (
    <div className="flex flex-col items-center justify-center p-2">
      <div className="relative inline-block w-24 h-24">
        <svg width="96" height="96" className="-rotate-90">
          <circle cx="48" cy="48" r="40" fill="none" stroke="#f1f5f9" strokeWidth="7" />
          <circle
            cx="48" cy="48" r="40" fill="none"
            stroke={cfg.color} strokeWidth="7"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-2xl font-bold font-mono tracking-tight" style={{ color: cfg.color }}>
            {score}
          </span>
          <span className="text-[10px] text-slate-400 font-medium uppercase">
            Risk Index
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs font-semibold px-2.5 py-0.5 rounded-full border"
        style={{ color: cfg.badgeText, borderColor: cfg.border, backgroundColor: cfg.badgeBg }}
      >
        {cfg.label}
      </div>
    </div>
  )
}

// ── QR Scanner Component ──────────────────────────────────────────────────────
function QrScanner({ onDecoded }) {
  const [mode, setMode] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [decoded, setDecoded] = useState(null)
  const [error, setError] = useState(null)
  const videoRef = useRef(null)
  const canvasRef = useRef(null)
  const streamRef = useRef(null)
  const animFrameRef = useRef(null)

  const stopCamera = useCallback(() => {
    if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current)
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => t.stop())
      streamRef.current = null
    }
    setScanning(false)
  }, [])

  useEffect(() => () => stopCamera(), [stopCamera])

  const startCamera = async () => {
    setError(null)
    setDecoded(null)
    setMode('camera')
    setScanning(true)
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' }
      })
      streamRef.current = stream
      if (videoRef.current) {
        videoRef.current.srcObject = stream
        videoRef.current.play()
        requestAnimationFrame(tick)
      }
    } catch {
      setError('Camera access denied or unavailable. Please use image upload instead.')
      setScanning(false)
    }
  }

  const tick = () => {
    if (!videoRef.current || !canvasRef.current) return
    const video = videoRef.current
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth
      canvas.height = video.videoHeight
      ctx.drawImage(video, 0, 0)
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const code = jsQR(imageData.data, imageData.width, imageData.height)
      if (code) {
        stopCamera()
        setDecoded(code.data)
        onDecoded(code.data)
        return
      }
    }
    animFrameRef.current = requestAnimationFrame(tick)
  }

  const handleImageUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setMode('upload')
    setError(null)
    setDecoded(null)

    try {
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      const img = new Image()
      const objectUrl = URL.createObjectURL(file)
      img.onload = () => {
        canvas.width = img.width
        canvas.height = img.height
        ctx.drawImage(img, 0, 0)
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
        const code = jsQR(imageData.data, imageData.width, imageData.height)
        URL.revokeObjectURL(objectUrl)
        if (code) {
          setDecoded(code.data)
          onDecoded(code.data)
        } else {
          setError('No QR code detected in this image. Please upload a clear photo.')
        }
      }
      img.onerror = () => {
        URL.revokeObjectURL(objectUrl)
        setError('Failed to read image. Please use PNG, JPG, or WEBP.')
      }
      img.src = objectUrl
    } catch (err) {
      setError('QR decoder error: ' + err.message)
    }
  }

  return (
    <div className="space-y-4">
      {!mode && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <button
            onClick={startCamera}
            className="human-card p-6 flex flex-col items-center justify-center text-center cursor-pointer hover:border-slate-400 bg-white"
          >
            <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center mb-3 text-slate-700">
              <Camera className="w-5 h-5" />
            </div>
            <div className="text-sm font-semibold text-slate-900">Scan with Camera</div>
            <div className="text-xs text-slate-500 mt-1">Real-time optical scanner</div>
          </button>

          <label className="human-card p-6 flex flex-col items-center justify-center text-center cursor-pointer hover:border-slate-400 bg-white">
            <div className="w-10 h-10 rounded-lg bg-slate-100 flex items-center justify-center mb-3 text-slate-700">
              <Upload className="w-5 h-5" />
            </div>
            <div className="text-sm font-semibold text-slate-900">Upload QR Image</div>
            <div className="text-xs text-slate-500 mt-1">PNG, JPG, or screenshot</div>
            <input type="file" accept="image/*" onChange={handleImageUpload} className="hidden" />
          </label>
        </div>
      )}

      {mode === 'camera' && (
        <div className="space-y-3">
          <div className="relative rounded-xl overflow-hidden bg-black border border-slate-200 max-h-64 flex items-center justify-center">
            <video ref={videoRef} className="w-full h-full object-cover" muted playsInline />
            <canvas ref={canvasRef} className="hidden" />
            {scanning && (
              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-40 h-40 border-2 border-white rounded-xl" />
              </div>
            )}
          </div>
          <button
            onClick={() => { stopCamera(); setMode(null) }}
            className="btn-secondary w-full py-2 text-xs font-medium cursor-pointer"
          >
            Cancel Camera
          </button>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {decoded && (
        <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-1.5">
          <div className="flex items-center gap-2 text-emerald-700 font-semibold text-[11px]">
            <CheckCircle2 className="w-4 h-4" />
            <span>QR Destination Decoded Safely</span>
          </div>
          <div className="font-mono text-slate-800 break-all bg-white p-2.5 rounded-lg border border-slate-200">
            {decoded}
          </div>
          <p className="text-[11px] text-slate-500">
            Running multi-layer threat analysis before navigating...
          </p>
        </div>
      )}
    </div>
  )
}

// ── Safe Preview Modal ────────────────────────────────────────────────────────
function SafePreviewModal({ url, onClose, onProceed }) {
  let parsedUrl = { protocol: '', host: '', pathname: '', search: '' }
  try {
    const u = new URL(url.startsWith('http') ? url : `http://${url}`)
    parsedUrl = { protocol: u.protocol, host: u.host, pathname: u.pathname, search: u.search }
  } catch {
    parsedUrl = { protocol: 'unknown', host: url, pathname: '', search: '' }
  }

  return (
    <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] animate-in fade-in duration-150">
      <div className="human-card w-full max-w-lg bg-white p-6 shadow-xl relative border border-slate-200">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-9 h-9 rounded-lg bg-rose-50 flex items-center justify-center text-rose-600 shrink-0">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-900 m-0">
              Safe Preview Sandbox
            </h3>
            <span className="text-xs text-slate-500">Automatic navigation halted for your protection</span>
          </div>
        </div>

        <p className="text-xs text-slate-600 leading-relaxed mb-4">
          Significant threat indicators detected on this target. Inspect the dissected destination elements below:
        </p>

        {/* Dissected URL components */}
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs space-y-2 mb-5 text-slate-700">
          <div className="flex justify-between border-b border-slate-200 pb-1.5">
            <span className="text-slate-500">Protocol:</span>
            <span className={parsedUrl.protocol.includes('https') ? 'text-emerald-700 font-semibold' : 'text-rose-600 font-semibold'}>
              {parsedUrl.protocol}
            </span>
          </div>
          <div className="flex justify-between border-b border-slate-200 pb-1.5">
            <span className="text-slate-500">Target Host:</span>
            <span className="text-slate-900 font-bold">{parsedUrl.host}</span>
          </div>
          <div className="flex justify-between border-b border-slate-200 pb-1.5">
            <span className="text-slate-500">Path Route:</span>
            <span className="text-slate-700">{parsedUrl.pathname || '/'}</span>
          </div>
          {parsedUrl.search && (
            <div className="flex justify-between">
              <span className="text-slate-500">Parameters:</span>
              <span className="text-amber-700 break-all max-w-[260px]">{parsedUrl.search}</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onClose}
            className="btn-primary flex-1 py-2 text-xs font-medium flex items-center justify-center gap-2 cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Go Back to Safety</span>
          </button>
          <button
            onClick={onProceed}
            className="btn-secondary px-4 py-2 text-xs font-medium flex items-center gap-1.5 cursor-pointer text-slate-600"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>Proceed (Risk)</span>
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Feedback Modal ────────────────────────────────────────────────────────────
function FeedbackModal({ scanResult, onClose }) {
  const [feedback, setFeedback] = useState('CORRECT')
  const [suggested, setSuggested] = useState(scanResult.label)
  const [comments, setComments] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [done, setDone] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    await submitFeedback({
      threat_log_id: scanResult.scan_id,
      url: scanResult.url,
      feedback,
      suggested_label: feedback === 'INCORRECT' ? suggested : scanResult.label,
      comments,
    })
    setSubmitting(false)
    setDone(true)
    setTimeout(() => { onClose() }, 1500)
  }

  return (
    <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] animate-in fade-in duration-150">
      <div className="human-card w-full max-w-md bg-white p-6 shadow-xl relative border border-slate-200">
        {done ? (
          <div className="text-center py-6">
            <CheckCircle2 className="w-10 h-10 text-emerald-600 mx-auto mb-2" />
            <h3 className="text-base font-semibold text-slate-900 mb-1">Feedback Submitted</h3>
            <p className="text-xs text-slate-500">
              Thank you. Verified feedback enters the curation pipeline for retraining.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <h3 className="text-base font-semibold text-slate-900 mb-1">Detection Feedback</h3>
              <p className="text-xs text-slate-500">
                Was this verdict accurate? Contributed feedback is reviewed for dataset refinement.
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {['CORRECT', 'INCORRECT'].map(opt => (
                <button
                  key={opt}
                  type="button"
                  onClick={() => setFeedback(opt)}
                  className={`p-2 rounded-lg border text-xs font-medium cursor-pointer transition ${
                    feedback === opt
                      ? 'bg-slate-900 text-white border-slate-900'
                      : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  {opt === 'CORRECT' ? 'Accurate Verdict' : 'Incorrect Prediction'}
                </button>
              ))}
            </div>

            {feedback === 'INCORRECT' && (
              <div>
                <label className="block text-xs text-slate-700 mb-1 font-medium">True Classification</label>
                <select
                  value={suggested}
                  onChange={e => setSuggested(e.target.value)}
                  className="w-full p-2 rounded-lg bg-white border border-slate-300 text-slate-800 text-xs focus:outline-none"
                >
                  <option value="LEGIT">Legitimate (Clean)</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="PHISHING">Phishing / Malicious Scam</option>
                </select>
              </div>
            )}

            <div>
              <label className="block text-xs text-slate-700 mb-1 font-medium">Context Notes (Optional)</label>
              <textarea
                value={comments}
                onChange={e => setComments(e.target.value)}
                placeholder="e.g. Authentic university subdomain or internal portal"
                rows={3}
                className="w-full p-2.5 rounded-lg bg-white border border-slate-300 text-slate-800 placeholder:text-slate-400 text-xs focus:outline-none"
              />
            </div>

            <div className="flex gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="btn-secondary flex-1 py-2 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="btn-primary flex-1 py-2 text-xs font-medium cursor-pointer disabled:opacity-60"
              >
                {submitting ? 'Submitting...' : 'Submit'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

// ── Result Panel ──────────────────────────────────────────────────────────────
function ResultPanel({ result, inputType, onOpenPreview }) {
  const [showFeedback, setShowFeedback] = useState(false)
  const [copiedFp, setCopiedFp] = useState(false)
  const [copiedDomain, setCopiedDomain] = useState(false)

  const verdictLabel = result.verdict || result.label || 'LEGITIMATE'
  const cfg = getRiskConfig(verdictLabel, result.internal_state)
  const rb = result.risk_breakdown || {}
  const intel = result.threat_intelligence || {}
  const tim = result.threat_intelligence_match || null
  const redirectInfo = result.redirect_info || null
  const fingerprint = result.threat_fingerprint || intel.fingerprint || ''
  const evidenceList = result.evidence && result.evidence.length > 0 ? result.evidence : (result.explainability || [])
  const isInsufficientEvidence = result.internal_state === 'INSUFFICIENT_EVIDENCE'
  const isKnownThreat = tim && tim.is_known_threat
  const tda = result.trusted_domain_analysis || null

  return (
    <div className="mt-6 space-y-4 animate-in fade-in duration-200">
      {showFeedback && (
        <FeedbackModal scanResult={result} onClose={() => setShowFeedback(false)} />
      )}

      {/* ── 1. KNOWN THREAT BANNER ── */}
      {isKnownThreat && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-rose-600 shrink-0 mt-0.5 sm:mt-0" />
            <div>
              <div className="text-sm font-semibold text-rose-900">
                CONFIRMED THREAT SIGNATURE: {String(tim.source || 'GLOBAL_DATABASE').toUpperCase()}
              </div>
              <div className="text-xs text-rose-700 mt-0.5">
                Target identified in verified feeds as <strong>{tim.threat_type || 'Phishing Scam'}</strong>.
              </div>
            </div>
          </div>
          <span className="text-[11px] font-semibold px-2.5 py-0.5 rounded-full bg-rose-100 text-rose-800 border border-rose-200 font-mono shrink-0">
            99.9% Confidence
          </span>
        </div>
      )}

      {/* ── 2. INSUFFICIENT EVIDENCE BANNER ── */}
      {isInsufficientEvidence && (
        <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-amber-800 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-amber-900">
              Unresolved Destination / Incomplete DNS
            </div>
            <div className="text-xs text-amber-700 mt-0.5">
              Domain does not resolve or host failed to respond. Unreachable sites are not passed as legitimate without verified proof.
            </div>
          </div>
        </div>
      )}

      {/* ── 3. MAIN SCORE & VERDICT HERO CARD ── */}
      <div
        className="human-card p-6 relative overflow-hidden bg-white"
        style={{ borderColor: cfg.border }}
      >
        <div className="grid grid-cols-1 md:grid-cols-[130px_1fr] gap-6 items-center">
          <ScoreRing
            score={result.risk_score ?? result.threat_score ?? 0}
            label={verdictLabel}
            internalState={result.internal_state}
          />

          <div className="space-y-3 text-left">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium px-2.5 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                {result.threat_category || 'General Web Services'}
              </span>
              <span className="text-xs font-medium px-2 py-0.5 rounded-md bg-slate-50 text-slate-500 border border-slate-200">
                {inputType} Inspection
              </span>
              <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-slate-50 text-slate-500 border border-slate-200">
                Confidence: {Math.round((result.confidence || 0.85) * 100)}%
              </span>
              {result.evidence_source && (
                <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200">
                  {result.evidence_source}
                </span>
              )}
            </div>

            <div>
              <h2 className="text-xl font-bold tracking-tight text-slate-900">
                {cfg.label}
              </h2>
              <p className="text-xs sm:text-sm text-slate-600 mt-1 leading-relaxed">
                {cfg.summary}
              </p>
            </div>

            {/* Target URL with Copy */}
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-800">
              <span className="truncate flex-1 text-slate-700">{result.url}</span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(result.url)
                  setCopiedDomain(true)
                  setTimeout(() => setCopiedDomain(false), 2000)
                }}
                className="text-[11px] px-2 py-1 rounded bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 flex items-center gap-1 cursor-pointer"
                title="Copy Target URL"
              >
                <Copy className="w-3 h-3 text-slate-500" />
                <span>{copiedDomain ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Action Bar */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              {verdictLabel !== 'LEGITIMATE' && verdictLabel !== 'LEGIT' && (
                <button
                  onClick={onOpenPreview}
                  className="px-3 py-1.5 rounded-lg bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-800 text-xs font-medium flex items-center gap-1.5 cursor-pointer transition"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Inspect in Safe Sandbox</span>
                </button>
              )}
              <button
                onClick={() => setShowFeedback(true)}
                className="px-3 py-1.5 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-600 hover:text-slate-900 text-xs font-medium flex items-center gap-1.5 cursor-pointer transition"
              >
                <ThumbsUp className="w-3.5 h-3.5" />
                <span>Submit Feedback</span>
              </button>
            </div>
          </div>
        </div>

        {/* Action Advice */}
        <div className="mt-4 pt-3 border-t border-slate-100 flex items-start gap-2 text-xs text-slate-600">
          <ShieldCheck className="w-4 h-4 text-slate-700 shrink-0 mt-0.5" />
          <span><strong>Action Advice:</strong> {cfg.actionAdvice}</span>
        </div>
      </div>

      {/* ── 4. REDIRECT CHAIN INSPECTION ── */}
      {redirectInfo && (
        <div className="human-card p-5 space-y-3 bg-white border-slate-200">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
              <CornerDownRight className="w-4 h-4 text-slate-600" />
              <span>Redirect Path & Navigation Inspection</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`text-[11px] font-medium px-2 py-0.5 rounded-md border ${
                redirectInfo.is_cross_domain
                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                {redirectInfo.is_cross_domain ? 'Cross-Domain Redirection' : 'Direct / Same-Origin'}
              </span>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-slate-100 text-slate-600 border border-slate-200">
                {redirectInfo.hops || 0} Hops
              </span>
            </div>
          </div>

          {redirectInfo.chain && redirectInfo.chain.length > 0 ? (
            <div className="space-y-1.5">
              {redirectInfo.chain.map((step, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 text-xs"
                >
                  <div className="flex items-center gap-2 truncate font-mono">
                    <span className="text-slate-900 font-semibold shrink-0">Hop {step.hop}:</span>
                    <span className="truncate text-slate-700">{step.url}</span>
                  </div>
                  <span className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded shrink-0 ${
                    step.status >= 300 && step.status < 400
                      ? 'bg-amber-100 text-amber-800'
                      : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    HTTP {step.status}
                  </span>
                </div>
              ))}
              {redirectInfo.final_url && redirectInfo.final_url !== result.url && (
                <div className="text-xs text-slate-500 pt-1">
                  Final Destination: <span className="font-mono text-slate-800 font-medium">{redirectInfo.final_url}</span>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500">
              Direct navigation to destination (No intermediary cloaking detected).
            </p>
          )}
        </div>
      )}

      {/* ── 5. BRAND REGISTRY VERIFICATION ── */}
      {tda && (
        <div className="human-card p-5 space-y-3 bg-white border-slate-200">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
              {tda.is_trusted ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (tda.match_level && tda.match_level.includes('IMPERSONATION')) ? (
                <ShieldAlert className="w-4 h-4 text-rose-600" />
              ) : (
                <Shield className="w-4 h-4 text-slate-600" />
              )}
              <span>Brand Registry Verification</span>
            </div>

            <div className="flex items-center gap-1.5 flex-wrap">
              {tda.brand_name && (
                <span className="text-[11px] font-medium px-2 py-0.5 rounded-md bg-slate-100 text-slate-800 border border-slate-200">
                  Target: {tda.brand_name}
                </span>
              )}
              <span className={`text-[11px] font-medium px-2 py-0.5 rounded-md ${
                tda.is_trusted ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-slate-100 text-slate-600 border border-slate-200'
              }`}>
                {tda.match_level}
              </span>
            </div>
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
            <div>
              <span className="text-slate-500">Root Suffix (PSL): </span>
              <span className="text-slate-900 font-semibold">{tda.registrable_domain || 'N/A'}</span>
            </div>
            <div>
              <span className="text-slate-500">Status: </span>
              <span className={tda.is_trusted ? 'text-emerald-700 font-semibold' : 'text-amber-700 font-semibold'}>
                {tda.status || 'UNVERIFIED'}
              </span>
            </div>
          </div>

          {tda.reasons && tda.reasons.length > 0 && (
            <div className="space-y-1 text-xs">
              {tda.reasons.map((r, i) => (
                <div key={i} className="text-slate-600 flex items-start gap-2">
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── 6. EXPLAINABLE AI EVIDENCE ── */}
      {evidenceList.length > 0 && (
        <div className="human-card p-5 space-y-3 bg-white border-slate-200">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
            <AlertCircle className="w-4 h-4 text-slate-600" />
            <span>Decision Factors (Explainable Features)</span>
          </div>
          <div className="space-y-1.5">
            {evidenceList.map((item, idx) => {
              const impact = (item.impact || 'MEDIUM').toUpperCase()
              const isBenign = impact === 'BENIGN'
              const isCritical = impact === 'CRITICAL'
              const isHigh = impact === 'HIGH'
              const badgeStyle = isBenign
                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : isCritical
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : isHigh
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : 'bg-amber-50 text-amber-700 border-amber-200'

              return (
                <div
                  key={idx}
                  className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 text-xs"
                >
                  <div className="flex items-center gap-2 text-slate-800">
                    <span className={isBenign ? 'text-emerald-600 font-bold' : 'text-slate-400'}>
                      •
                    </span>
                    <span>{item.factor}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {item.source && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white text-slate-500 border border-slate-200 hidden sm:inline">
                        {item.source}
                      </span>
                    )}
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full border ${badgeStyle}`}>
                      {impact}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── 7. RISK BREAKDOWN BARS ── */}
      <div className="human-card p-5 space-y-4 bg-white border-slate-200">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
          <TrendingUp className="w-4 h-4 text-slate-600" />
          <span>Multi-Layer Risk Signal Decomposition</span>
        </div>
        <RiskBar value={rb.url_risk ?? result.threat_score ?? 0} label="Lexical & Structural URL Risk (35%)" />
        <RiskBar value={rb.webpage_risk ?? 0} label="DOM & Form Credential Risk (25%)" />
        <RiskBar value={rb.behavior_risk ?? 0} label="Behavioral Anomaly Risk (20%)" />
        <RiskBar value={rb.threat_intel_score ?? (isKnownThreat ? 100 : 0)} label="Threat Intelligence Match (15%)" color="#0284c7" />
        <RiskBar value={rb.ai_deception_score ?? 0} label="Synthetic / Deception Indicator (5%)" color="#9333ea" />
      </div>

      {/* ── 8. THREAT INTEL & IMMUTABLE LEDGER ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="human-card p-5 space-y-2 bg-white border-slate-200">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
            <Database className="w-4 h-4 text-slate-600" />
            <span>Threat Intelligence Feeds</span>
          </div>
          <div className="text-xs font-medium text-slate-800">
            {isKnownThreat
              ? `Active Match: ${tim.source}`
              : intel.previously_detected
              ? `Previously Flagged (${intel.prior_detection_count} reports)`
              : 'Clean: No active match in known abuse databases'}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Sources: OpenPhish • URLhaus • PhishTank • Community Feeds
          </div>
        </div>

        <div className="human-card p-5 space-y-2 bg-white border-slate-200">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-900">
            <Link2 className="w-4 h-4 text-slate-600" />
            <span>Immutable Blockchain Ledger</span>
          </div>
          {result.logged_to_blockchain ? (
            <div>
              <div className="text-xs font-semibold text-emerald-700">Recorded On-Chain</div>
              <div className="text-[11px] text-slate-500 font-mono truncate mt-0.5">
                Hash: {result.block_hash ? result.block_hash.slice(0, 24) + '...' : 'Recorded'}
              </div>
            </div>
          ) : (
            <div className="text-xs text-slate-500">
              {verdictLabel === 'LEGITIMATE' || verdictLabel === 'LEGIT'
                ? 'No threat to record (Verified clean)'
                : 'Queued for mining block verification'}
            </div>
          )}
        </div>
      </div>

      {/* ── 9. FINGERPRINT & IDENTIFIER ── */}
      <div className="human-card p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs bg-white border-slate-200">
        <div className="flex items-center gap-2 text-slate-700 font-mono">
          <Fingerprint className="w-4 h-4 shrink-0 text-slate-500" />
          <span className="font-semibold">SHA-256:</span>
          <span className="truncate max-w-[280px] sm:max-w-md text-slate-600">
            {fingerprint || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
          </span>
        </div>
        <button
          onClick={() => {
            if (fingerprint) {
              navigator.clipboard.writeText(fingerprint)
              setCopiedFp(true)
              setTimeout(() => setCopiedFp(false), 2000)
            }
          }}
          className="btn-secondary px-3 py-1 text-xs font-medium flex items-center gap-1.5 cursor-pointer shrink-0"
        >
          <Copy className="w-3.5 h-3.5 text-slate-500" />
          <span>{copiedFp ? 'Copied Hash' : 'Copy Hash'}</span>
        </button>
      </div>

    </div>
  )
}

// ── Main ScanPage Component ───────────────────────────────────────────────────
export default function ScanPage() {
  const { user, isAuthenticated, openAuthModal } = useAuth()
  const [activeTab, setActiveTab] = useState('url')
  const [urlInput, setUrlInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [safePreviewUrl, setSafePreviewUrl] = useState(null)

  // ── Website Audit State (Modules 1 - 10) ───────────────────────────────────
  const [auditResult, setAuditResult] = useState(null)
  const [auditLoading, setAuditLoading] = useState(false)
  const [isOwnerAuthorized, setIsOwnerAuthorized] = useState(false)
  const [showVerifyModal, setShowVerifyModal] = useState(false)
  const [verifyDomainInput, setVerifyDomainInput] = useState('')
  const [verifyToken] = useState('phishsense-audit-2026')
  const [verifyStatus, setVerifyStatus] = useState(null)
  const [verifyingDns, setVerifyingDns] = useState(false)

  const handleUrlScan = async (e) => {
    e?.preventDefault()
    if (!urlInput.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    setAuditResult(null)
    try {
      // Clean scan without injecting scanner search-bar telemetry into target verdict
      const data = await scanUrl(urlInput.trim(), null)
      if (data) {
        if (data.status === 'RATE_LIMITED' || data.verdict === 'RATE_LIMITED') {
          setError(data.error_message || 'Rate limit reached: Maximum 30 scans per 5 minutes. Please wait a moment.')
        } else {
          setResult({ ...data, input_type: 'URL' })
        }
      } else {
        setError('Scan failed. Please verify the link format.')
      }
    } catch {
      setError('Service unavailable. Please retry shortly.')
    } finally {
      setLoading(false)
    }
  }

  const handleQrDecoded = async (decodedUrl) => {
    setLoading(true)
    setError(null)
    setResult(null)
    setAuditResult(null)
    try {
      const data = await scanQr(decodedUrl)
      if (data) {
        if (data.status === 'RATE_LIMITED' || data.verdict === 'RATE_LIMITED') {
          setError(data.error_message || 'Rate limit reached. Please wait a moment before rescanning.')
        } else {
          setResult({ ...data, input_type: 'QR', qr_decoded_url: decodedUrl })
        }
      } else {
        setError('QR destination analysis failed.')
      }
    } catch {
      setError('Service error during QR analysis.')
    } finally {
      setLoading(false)
    }
  }

  const handleWebsiteAudit = async (e) => {
    e?.preventDefault()
    if (!urlInput.trim()) return
    setAuditLoading(true)
    setError(null)
    setAuditResult(null)
    setResult(null)
    try {
      const data = await auditWebsite(urlInput.trim(), isOwnerAuthorized)
      if (data && data.categories && data.categories.length > 0) {
        setAuditResult(data)
      } else if (data && data.error) {
        setError(data.error)
      } else {
        setError('Audit service was unable to evaluate this destination.')
      }
    } catch {
      setError('Audit service temporarily unavailable. Please retry shortly.')
    } finally {
      setAuditLoading(false)
    }
  }

  const handleVerifyOwnership = async (e) => {
    e?.preventDefault()
    if (!verifyDomainInput.trim()) return
    setVerifyingDns(true)
    setVerifyStatus('Querying DNS TXT records for verification tag...')
    try {
      const res = await verifyDomainOwnership(verifyDomainInput.trim(), verifyToken)
      if (res && res.verified) {
        setIsOwnerAuthorized(true)
        setVerifyStatus('Ownership verified! Authorized assessment mode activated.')
        setTimeout(() => setShowVerifyModal(false), 1600)
      } else {
        setVerifyStatus(res?.message || 'Verification record not found. Please add the DNS TXT record and retry.')
      }
    } catch {
      setVerifyStatus('DNS query failed. Please verify domain name.')
    } finally {
      setVerifyingDns(false)
    }
  }

  return (
    <div className="min-h-[calc(100vh-64px)] bg-[#f8fafc] text-slate-900 py-10 px-4 sm:px-6">
      {safePreviewUrl && (
        <SafePreviewModal
          url={safePreviewUrl}
          onClose={() => setSafePreviewUrl(null)}
          onProceed={() => {
            window.open(safePreviewUrl, '_blank', 'noopener,noreferrer')
            setSafePreviewUrl(null)
          }}
        />
      )}

      <div className={`mx-auto space-y-6 transition-all ${activeTab === 'audit' ? 'max-w-4xl' : 'max-w-3xl'}`}>
        
        {/* Header */}
        <div className="text-center space-y-2.5">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white border border-slate-200 text-slate-700 text-xs font-medium shadow-sm">
            <Shield className="w-3.5 h-3.5 text-slate-700" />
            <span>Multi-Layer Threat Engine</span>
          </div>
          <h1 className="text-2xl sm:text-4xl font-bold tracking-tight text-slate-900">
            {activeTab === 'audit' ? 'Website Security & Health Audit' : 'Inspect Any Link, QR, or Webpage'}
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 max-w-lg mx-auto">
            {activeTab === 'audit'
              ? 'Comprehensive 10-category inspection: Outdated software, known CVEs, TLS, security headers, RDAP age & website availability.'
              : 'Test links in a secure sandbox before opening them on your phone or PC.'}
          </p>

          {/* User Status / Mode indicator */}
          <div className="pt-0.5">
            {isAuthenticated ? (
              <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-medium">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                <span>Signed in as <strong>{user?.email}</strong> — Scans saved automatically.</span>
              </div>
            ) : (
              <div className="inline-flex items-center gap-1.5 text-slate-500 text-xs">
                <span>Free Guest Scanner</span>
                <span>•</span>
                <button
                  onClick={openAuthModal}
                  className="text-slate-900 underline font-medium cursor-pointer"
                >
                  Sign in
                </button>
                <span>only to save history.</span>
              </div>
            )}
          </div>
        </div>

        {/* Tab Selection */}
        <div className="flex p-1 rounded-xl bg-slate-100 border border-slate-200 gap-1">
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => {
                setActiveTab(key)
                setResult(null)
                setAuditResult(null)
                setError(null)
                setUrlInput('')
              }}
              className={`flex-1 py-2 px-3 rounded-lg text-xs sm:text-sm font-medium flex items-center justify-center gap-2 transition-all cursor-pointer ${
                activeTab === key
                  ? 'bg-white text-slate-900 shadow-sm border border-slate-200 font-semibold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="w-4 h-4 text-slate-500" />
              <span>{label}</span>
            </button>
          ))}
        </div>

        {/* URL Mode */}
        {activeTab === 'url' && (
          <div className="space-y-3">
            <form onSubmit={handleUrlScan} className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <ScanLine className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
                <input
                  type="text"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  placeholder="Paste URL (e.g., https://paypa1-security-verification.xyz)"
                  required
                  className="clean-input w-full pl-10 pr-4 py-2.5 text-sm font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={loading || !urlInput.trim()}
                className="btn-primary flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 shrink-0 font-medium"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ScanLine className="w-4 h-4" />}
                <span>{loading ? 'Analyzing...' : 'Scan Link'}</span>
              </button>
            </form>

            {/* Quick-test Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs pt-0.5">
              <span className="text-slate-500">Try sample:</span>
              {PRESET_SAMPLES.map(({ label, url, tag }) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setUrlInput(url)}
                  className="px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-1.5 transition cursor-pointer font-medium text-xs shadow-xs"
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${
                    tag === 'Safe' ? 'bg-emerald-500' : tag === 'Phishing' ? 'bg-rose-500' : 'bg-amber-500'
                  }`} />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* QR Mode */}
        {activeTab === 'qr' && (
          <div className="space-y-3">
            <QrScanner onDecoded={handleQrDecoded} />
            <div className="p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-xs flex items-center gap-2">
              <Lock className="w-4 h-4 shrink-0 text-amber-600" />
              <span>QR Policy: Destination links are isolated and analyzed in a sandbox prior to browser navigation.</span>
            </div>
          </div>
        )}

        {/* Website Audit Mode (10 Categories) */}
        {activeTab === 'audit' && (
          <div className="space-y-4">
            {/* Mode & Ownership Bar */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 p-3 rounded-xl bg-white border border-slate-200 text-xs">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-slate-700">
                  Mode: <strong>{isOwnerAuthorized ? 'Owner-Authorized Assessment' : 'Public Passive Assessment'}</strong>
                </span>
                <span className="text-slate-400">({isOwnerAuthorized ? 'Authorized extended checks enabled' : 'Safe non-intrusive inspection'})</span>
              </div>
              <button
                type="button"
                onClick={() => setShowVerifyModal(true)}
                className="text-xs font-semibold text-slate-800 hover:text-slate-950 underline cursor-pointer"
              >
                {isOwnerAuthorized ? 'Manage Domain Authorization' : 'Verify Domain Ownership'}
              </button>
            </div>

            <form onSubmit={handleWebsiteAudit} className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <Globe className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
                <input
                  type="text"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  placeholder="https://example.com or domain.org"
                  required
                  className="clean-input w-full pl-10 pr-4 py-2.5 text-sm font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={auditLoading || !urlInput.trim()}
                className="btn-primary flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 shrink-0 font-medium"
              >
                {auditLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                <span>{auditLoading ? 'Auditing 10 Categories...' : 'Run Security Audit'}</span>
              </button>
            </form>

            {/* Quick-test Presets for Audit */}
            <div className="flex flex-wrap items-center gap-2 text-xs pt-0.5">
              <span className="text-slate-500">Audit presets:</span>
              {AUDIT_PRESETS.map(({ label, url }) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setUrlInput(url)}
                  className="px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-1.5 transition cursor-pointer font-medium text-xs shadow-xs"
                >
                  <Globe className="w-3 h-3 text-slate-400" />
                  <span>{label}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Loading state for Quick Scan */}
        {loading && (
          <div className="human-card p-10 text-center space-y-2.5 animate-in fade-in bg-white border-slate-200">
            <Loader2 className="w-7 h-7 text-slate-700 animate-spin mx-auto" />
            <h3 className="text-sm font-semibold text-slate-900">Running Threat Pipeline</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Extracting domain indicators · Scanning redirect chains · Cross-checking threat ledger
            </p>
          </div>
        )}

        {/* Loading state for Website Audit */}
        {auditLoading && (
          <div className="human-card p-10 text-center space-y-3 animate-in fade-in bg-white border-slate-200">
            <Loader2 className="w-8 h-8 text-slate-800 animate-spin mx-auto" />
            <h3 className="text-base font-semibold text-slate-900">Executing 10-Category Security & Health Audit</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
              Fingerprinting tech stack · Correlating NVD CVE vulnerabilities · Checking TLS & CT logs · Evaluating security headers · Testing website health & broken resources
            </p>
          </div>
        )}

        {/* Error state */}
        {error && (
          <div className="p-3.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        {/* Quick Scan Results */}
        {!loading && result && activeTab !== 'audit' && (
          <ResultPanel
            result={result}
            inputType={result.input_type || activeTab.toUpperCase()}
            onOpenPreview={() => setSafePreviewUrl(result.url)}
          />
        )}

        {/* Website Audit Results (10 Categories) */}
        {!auditLoading && auditResult && activeTab === 'audit' && (
          <WebsiteAuditReport
            auditData={auditResult}
            onRescan={handleWebsiteAudit}
          />
        )}

        {/* Owner Verification Modal (Module 9) */}
        {showVerifyModal && (
          <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] animate-in fade-in duration-150">
            <div className="human-card w-full max-w-md bg-white p-6 shadow-xl relative border border-slate-200 space-y-4">
              <div className="flex items-center gap-2.5 pb-2 border-b border-slate-100">
                <ShieldCheck className="w-5 h-5 text-slate-900" />
                <h3 className="text-base font-bold text-slate-900 m-0">Verify Domain Ownership</h3>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                To activate <strong>Owner-Authorized Assessment</strong>, verify control of your domain by adding a DNS TXT record. This grants authorization without performing any intrusive or destructive actions.
              </p>
              
              <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs space-y-1.5 text-slate-800">
                <div className="text-[11px] text-slate-500 font-sans font-semibold">Required DNS TXT Record:</div>
                <div className="bg-white p-2 rounded border border-slate-200 break-all select-all text-slate-900 font-bold">
                  phishsense-verification={verifyToken}
                </div>
              </div>

              <form onSubmit={handleVerifyOwnership} className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 mb-1">Domain Name</label>
                  <input
                    type="text"
                    value={verifyDomainInput}
                    onChange={e => setVerifyDomainInput(e.target.value)}
                    placeholder="example.com"
                    required
                    className="clean-input w-full px-3 py-2 text-xs font-mono"
                  />
                </div>

                {verifyStatus && (
                  <div className={`p-2.5 rounded-lg text-xs ${
                    verifyStatus.includes('verified') || verifyStatus.includes('Verified')
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                      : 'bg-amber-50 text-amber-800 border border-amber-200'
                  }`}>
                    {verifyStatus}
                  </div>
                )}

                <div className="flex items-center gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => { setShowVerifyModal(false); setVerifyStatus(null) }}
                    className="btn-secondary flex-1 py-2 text-xs font-medium cursor-pointer"
                  >
                    Close
                  </button>
                  <button
                    type="submit"
                    disabled={verifyingDns || !verifyDomainInput.trim()}
                    className="btn-primary flex-1 py-2 text-xs font-medium cursor-pointer disabled:opacity-50"
                  >
                    {verifyingDns ? 'Checking DNS...' : 'Verify DNS Record'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

      </div>
    </div>
  )
}
