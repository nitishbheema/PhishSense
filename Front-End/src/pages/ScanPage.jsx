import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Shield, ScanLine, QrCode, Globe, AlertTriangle, CheckCircle2,
  XCircle, Link2, Activity, ChevronRight, Upload, Camera, Loader2,
  Info, Eye, Lock, Cpu, Database, TrendingUp, ThumbsUp, ThumbsDown,
  ExternalLink, ArrowLeft, Layers, Check, X, ShieldAlert, CornerDownRight,
  Fingerprint, Copy, ShieldCheck
} from 'lucide-react'
import jsQR from 'jsqr'
import { useBehaviorTracker } from '../hooks/useBehaviorTracker'
import { scanUrl, scanQr, analyzeWebsite, submitFeedback } from '../utils/api'
import { useAuth } from '../context/AuthContext'

// ── Constants ─────────────────────────────────────────────────────────────────
const TABS = [
  { key: 'url',     label: 'Scan URL',         icon: ScanLine, desc: 'Analyze any URL for domain impersonation and phishing patterns' },
  { key: 'qr',      label: 'Scan QR Code',      icon: QrCode,   desc: 'Safely decode QR code destination and analyze payload before navigation' },
  { key: 'website', label: 'Analyze Website',   icon: Globe,    desc: 'Deep inspection of DOM structure, forms, external scripts, and iframes' },
]

const RISK_CONFIG = {
  PHISHING:    { color: '#f87171', bg: '#2d0a0a', border: '#5a1515', label: 'PHISHING',                 badgeBg: '#451010' },
  SUSPICIOUS:  { color: '#fbbf24', bg: '#2a1f00', border: '#5a4a00', label: 'SUSPICIOUS',               badgeBg: '#3d2e00' },
  UNVERIFIED:  { color: '#f59e0b', bg: '#2a1700', border: '#603305', label: 'SUSPICIOUS (UNVERIFIED)',  badgeBg: '#451d02' },
  LEGITIMATE:  { color: '#4ade80', bg: '#0a2d16', border: '#1a5a30', label: 'LEGITIMATE',               badgeBg: '#0e3a1d' },
  LEGIT:       { color: '#4ade80', bg: '#0a2d16', border: '#1a5a30', label: 'LEGITIMATE',               badgeBg: '#0e3a1d' },
}

function getRiskConfig(label, internalState) {
  if (internalState === 'INSUFFICIENT_EVIDENCE') {
    return RISK_CONFIG.UNVERIFIED
  }
  const key = (label || '').toUpperCase()
  return RISK_CONFIG[key] || RISK_CONFIG.SUSPICIOUS
}

function RiskBar({ value, color, label }) {
  const pct = Math.min(100, Math.max(0, value))
  const c = value > 65 ? '#f87171' : value > 35 ? '#fbbf24' : '#4ade80'
  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
        <span style={{ fontSize: '12px', color: '#888' }}>{label}</span>
        <span style={{ fontSize: '12px', fontWeight: 700, color: color || c }}>{value}%</span>
      </div>
      <div style={{ height: '6px', background: '#1a1a2e', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{
          width: `${pct}%`, height: '100%', borderRadius: '3px',
          background: color || c, transition: 'width 0.6s ease',
        }} />
      </div>
    </div>
  )
}

function ScoreRing({ score, label, internalState }) {
  const cfg = getRiskConfig(label, internalState)
  const circumference = 2 * Math.PI * 45
  const strokeDashoffset = circumference - (score / 100) * circumference
  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ position: 'relative', display: 'inline-block', width: 120, height: 120 }}>
        <svg width="120" height="120" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="60" cy="60" r="45" fill="none" stroke="#1a1a2e" strokeWidth="10" />
          <circle
            cx="60" cy="60" r="45" fill="none"
            stroke={cfg.color} strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
        </svg>
        <div style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          textAlign: 'center',
        }}>
          <div style={{ fontSize: '22px', fontWeight: 700, color: cfg.color }}>{score}</div>
          <div style={{ fontSize: '9px', color: '#666', fontWeight: 500 }}>RISK</div>
        </div>
      </div>
      <div style={{
        marginTop: '8px', fontSize: '12px', fontWeight: 700,
        color: cfg.color, letterSpacing: '0.5px',
      }}>{cfg.label}</div>
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
    <div>
      {!mode && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '1.5rem' }}>
          <button onClick={startCamera} style={{
            background: '#111120', border: '1px solid #1a1a2e', borderRadius: '10px',
            padding: '1.5rem', cursor: 'pointer', color: '#e8e8f0', textAlign: 'center',
          }}>
            <Camera size={28} color="#818cf8" style={{ margin: '0 auto 10px', display: 'block' }} />
            <div style={{ fontSize: '13px', fontWeight: 600 }}>Use Camera</div>
            <div style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>Real-time scanner</div>
          </button>
          <label style={{
            background: '#111120', border: '1px solid #1a1a2e', borderRadius: '10px',
            padding: '1.5rem', cursor: 'pointer', color: '#e8e8f0', textAlign: 'center', display: 'block',
          }}>
            <Upload size={28} color="#818cf8" style={{ margin: '0 auto 10px', display: 'block' }} />
            <div style={{ fontSize: '13px', fontWeight: 600 }}>Upload Image</div>
            <div style={{ fontSize: '11px', color: '#666', marginTop: '4px' }}>PNG, JPG, WEBP</div>
            <input type="file" accept="image/*" onChange={handleImageUpload} style={{ display: 'none' }} />
          </label>
        </div>
      )}

      {mode === 'camera' && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ position: 'relative', borderRadius: '10px', overflow: 'hidden', background: '#000' }}>
            <video ref={videoRef} style={{ width: '100%', display: 'block', maxHeight: '240px', objectFit: 'cover' }} muted playsInline />
            <canvas ref={canvasRef} style={{ display: 'none' }} />
            {scanning && (
              <div style={{
                position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
                border: '2px solid #818cf8', borderRadius: '8px', width: '160px', height: '160px', pointerEvents: 'none',
              }} />
            )}
          </div>
          <button onClick={() => { stopCamera(); setMode(null) }} style={{
            marginTop: '8px', width: '100%', padding: '8px', background: 'transparent',
            border: '1px solid #333', borderRadius: '8px', color: '#888', cursor: 'pointer', fontSize: '13px',
          }}>
            Cancel Camera
          </button>
        </div>
      )}

      {error && (
        <div style={{
          background: '#2d0a0a', border: '1px solid #5a1515', borderRadius: '8px',
          padding: '10px 14px', marginBottom: '1rem', display: 'flex', alignItems: 'center',
          gap: '8px', fontSize: '12px', color: '#f87171',
        }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {decoded && (
        <div style={{
          background: '#0a1a0f', border: '1px solid #1a3a25', borderRadius: '8px',
          padding: '12px 14px', marginBottom: '1rem',
        }}>
          <div style={{ fontSize: '11px', color: '#4ade80', fontWeight: 600, marginBottom: '4px' }}>
            ✓ QR CODE DECODED SAFELY
          </div>
          <div style={{ fontSize: '12px', color: '#e8e8f0', fontFamily: 'DM Mono, monospace', wordBreak: 'break-all' }}>
            {decoded}
          </div>
          <div style={{ fontSize: '10px', color: '#666', marginTop: '6px' }}>
            Running deep multi-input threat inspection on destination...
          </div>
        </div>
      )}
    </div>
  )
}

// ── Safe Preview Component (Section 23) ───────────────────────────────────────
function SafePreviewModal({ url, onClose, onProceed }) {
  let parsedUrl = { protocol: '', host: '', pathname: '', search: '' }
  try {
    const u = new URL(url.startsWith('http') ? url : `http://${url}`)
    parsedUrl = { protocol: u.protocol, host: u.host, pathname: u.pathname, search: u.search }
  } catch {
    parsedUrl = { protocol: 'unknown', host: url, pathname: '', search: '' }
  }

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center',
      justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div style={{
        background: '#0f0f1a', border: '1px solid #3a1515', borderRadius: '16px',
        maxWidth: '560px', width: '100%', padding: '2rem', boxShadow: '0 10px 40px rgba(0,0,0,0.6)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
          <div style={{ width: 40, height: 40, borderRadius: '10px', background: '#2d0a0a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <AlertTriangle size={22} color="#f87171" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '16px', color: '#f87171', fontWeight: 700 }}>
              Safe Preview Mode
            </h3>
            <span style={{ fontSize: '11px', color: '#888' }}>Automatic navigation halted for your protection</span>
          </div>
        </div>

        <p style={{ fontSize: '13px', color: '#bbb', lineHeight: 1.6, marginBottom: '1.2rem' }}>
          PhishSense detected significant threat indicators on this target. Inspect the dissected destination elements below before making any decision:
        </p>

        {/* Dissected URL components */}
        <div style={{ background: '#0a0a12', border: '1px solid #1a1a2e', borderRadius: '10px', padding: '12px', marginBottom: '1.5rem', fontFamily: 'DM Mono, monospace', fontSize: '11px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid #141424' }}>
            <span style={{ color: '#666' }}>Protocol:</span>
            <span style={{ color: parsedUrl.protocol.includes('https') ? '#4ade80' : '#f87171' }}>{parsedUrl.protocol}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid #141424' }}>
            <span style={{ color: '#666' }}>Target Host:</span>
            <span style={{ color: '#f87171', fontWeight: 700 }}>{parsedUrl.host}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid #141424' }}>
            <span style={{ color: '#666' }}>Path Route:</span>
            <span style={{ color: '#aaa' }}>{parsedUrl.pathname || '/'}</span>
          </div>
          {parsedUrl.search && (
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
              <span style={{ color: '#666' }}>Parameters:</span>
              <span style={{ color: '#fbbf24', wordBreak: 'break-all', maxWidth: '320px' }}>{parsedUrl.search}</span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={onClose} style={{
            flex: 1, padding: '11px', borderRadius: '8px', background: '#6366f1',
            color: '#fff', border: 'none', fontWeight: 600, fontSize: '13px', cursor: 'pointer',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
          }}>
            <ArrowLeft size={14} /> Go Back to Safety
          </button>
          <button onClick={onProceed} style={{
            padding: '11px 16px', borderRadius: '8px', background: 'transparent',
            border: '1px solid #5a1515', color: '#f87171', fontSize: '12px', cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: '6px',
          }}>
            <ExternalLink size={13} /> Proceed at Own Risk
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Feedback Modal (Section 20) ───────────────────────────────────────────────
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
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center',
      justifyContent: 'center', zIndex: 1000, padding: '1rem',
    }}>
      <div style={{
        background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '16px',
        maxWidth: '480px', width: '100%', padding: '2rem',
      }}>
        {done ? (
          <div style={{ textAlign: 'center', padding: '1rem' }}>
            <CheckCircle2 size={40} color="#4ade80" style={{ margin: '0 auto 12px', display: 'block' }} />
            <h3 style={{ color: '#e8e8f0', margin: '0 0 6px' }}>Feedback Logged</h3>
            <p style={{ color: '#888', fontSize: '13px', margin: 0 }}>
              Your feedback has been queued for human verification and model curation.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <h3 style={{ fontSize: '16px', color: '#e8e8f0', margin: '0 0 8px', fontWeight: 700 }}>
              Detection Feedback Loop
            </h3>
            <p style={{ fontSize: '12px', color: '#777', margin: '0 0 1.2rem', lineHeight: 1.5 }}>
              Help improve PhishSense. Verified feedback enters the research curation dataset for model retraining.
            </p>

            <div style={{ display: 'flex', gap: '8px', marginBottom: '1.2rem' }}>
              {['CORRECT', 'INCORRECT'].map(opt => (
                <button
                  key={opt} type="button" onClick={() => setFeedback(opt)}
                  style={{
                    flex: 1, padding: '10px', borderRadius: '8px', cursor: 'pointer',
                    fontSize: '13px', fontWeight: 600, border: '1px solid #1a1a2e',
                    background: feedback === opt ? (opt === 'CORRECT' ? '#0a2d16' : '#2d0a0a') : '#0a0a12',
                    color: feedback === opt ? (opt === 'CORRECT' ? '#4ade80' : '#f87171') : '#666',
                  }}>
                  {opt === 'CORRECT' ? '✓ Correct Detection' : '✗ Incorrect Prediction'}
                </button>
              ))}
            </div>

            {feedback === 'INCORRECT' && (
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '6px' }}>
                  What is the true classification?
                </label>
                <select
                  value={suggested} onChange={e => setSuggested(e.target.value)}
                  style={{
                    width: '100%', padding: '9px 12px', borderRadius: '8px', background: '#0a0a12',
                    border: '1px solid #1a1a2e', color: '#e8e8f0', fontSize: '13px',
                  }}>
                  <option value="LEGIT">Legitimate</option>
                  <option value="SUSPICIOUS">Suspicious</option>
                  <option value="PHISHING">Phishing / Malicious</option>
                </select>
              </div>
            )}

            <div style={{ marginBottom: '1.5rem' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#888', marginBottom: '6px' }}>
                Comments / Context (Optional)
              </label>
              <textarea
                value={comments} onChange={e => setComments(e.target.value)}
                placeholder="e.g. Legitimate internal university portal or brand sub-domain"
                rows={3}
                style={{
                  width: '100%', padding: '10px', borderRadius: '8px', background: '#0a0a12',
                  border: '1px solid #1a1a2e', color: '#e8e8f0', fontSize: '13px', boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button type="button" onClick={onClose} style={{
                flex: 1, padding: '10px', borderRadius: '8px', background: 'transparent',
                border: '1px solid #333', color: '#888', cursor: 'pointer', fontSize: '13px',
              }}>
                Cancel
              </button>
              <button type="submit" disabled={submitting} style={{
                flex: 1, padding: '10px', borderRadius: '8px', background: '#6366f1',
                color: '#fff', border: 'none', fontWeight: 600, cursor: 'pointer', fontSize: '13px',
              }}>
                {submitting ? 'Submitting...' : 'Submit Feedback'}
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

  const verdictLabel = result.verdict || result.label || 'LEGITIMATE'
  const cfg = getRiskConfig(verdictLabel, result.internal_state)
  const rb = result.risk_breakdown || {}
  const intel = result.threat_intelligence || {}
  const tim = result.threat_intelligence_match || null
  const redirectInfo = result.redirect_info || null
  const fingerprint = result.threat_fingerprint || intel.fingerprint || ''
  const sim = result.similarity_analysis || {}
  const evidenceList = result.evidence && result.evidence.length > 0 ? result.evidence : (result.explainability || [])
  const isInsufficientEvidence = result.internal_state === 'INSUFFICIENT_EVIDENCE'
  const isKnownThreat = tim && tim.is_known_threat
  const tda = result.trusted_domain_analysis || null

  return (
    <div style={{ marginTop: '1.5rem', animation: 'fadeIn 0.4s ease' }}>
      {showFeedback && (
        <FeedbackModal scanResult={result} onClose={() => setShowFeedback(false)} />
      )}

      {/* ── 1. KNOWN THREAT INTELLIGENCE BANNER ── */}
      {isKnownThreat && (
        <div style={{
          background: 'rgba(239, 68, 68, 0.15)',
          border: '1px solid #ef4444',
          borderRadius: '12px',
          padding: '14px 18px',
          marginBottom: '1rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '12px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <ShieldAlert size={26} color="#f87171" style={{ flexShrink: 0 }} />
            <div>
              <div style={{ fontSize: '14px', fontWeight: 800, color: '#f87171', letterSpacing: '0.3px' }}>
                KNOWN THREAT INTELLIGENCE MATCH: {String(tim.source || 'GLOBAL_DATABASE').toUpperCase()}
              </div>
              <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '3px' }}>
                Target positively identified in verified threat feeds as <strong>{tim.threat_type || 'Malicious Phishing Portal'}</strong>. Immediate block advised.
              </div>
            </div>
          </div>
          <span style={{
            fontSize: '11px', fontWeight: 800, padding: '4px 10px', borderRadius: '6px',
            background: '#451010', color: '#fca5a5', border: '1px solid #7f1d1d'
          }}>
            MATCH CONFIDENCE: 99.9%
          </span>
        </div>
      )}

      {/* ── 2. INSUFFICIENT EVIDENCE / UNVERIFIED BANNER ── */}
      {isInsufficientEvidence && (
        <div style={{
          background: 'rgba(245, 158, 11, 0.12)',
          border: '1px solid #f59e0b',
          borderRadius: '12px',
          padding: '14px 18px',
          marginBottom: '1rem',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}>
          <AlertTriangle size={26} color="#f59e0b" style={{ flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: '14px', fontWeight: 800, color: '#f59e0b' }}>
              INSUFFICIENT EVIDENCE / UNRESOLVED HOST
            </div>
            <div style={{ fontSize: '12px', color: '#cbd5e1', marginTop: '3px' }}>
              Target domain does not resolve in DNS or host failed to respond. Under PhishSense safety doctrine, unreachable destinations are never safe-washed as legitimate without verified proof.
            </div>
          </div>
        </div>
      )}

      {/* ── 3. MAIN SCORE & VERDICT HEADER ── */}
      <div style={{
        background: cfg.bg, border: `1px solid ${cfg.border}`,
        borderRadius: '12px', padding: '1.5rem', marginBottom: '1rem',
        display: 'grid', gridTemplateColumns: '120px 1fr', gap: '1.5rem', alignItems: 'center',
      }}>
        <ScoreRing score={result.risk_score ?? result.threat_score ?? 0} label={verdictLabel} internalState={result.internal_state} />
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', background: '#111120', border: '1px solid #1a1a2e', borderRadius: '4px', padding: '2px 8px', color: '#818cf8', fontWeight: 600 }}>
              {result.threat_category || 'General Web Services'}
            </span>
            <span style={{ fontSize: '11px', background: '#111120', border: '1px solid #1a1a2e', borderRadius: '4px', padding: '2px 8px', color: '#aaa' }}>
              {inputType} SCAN
            </span>
            <span style={{ fontSize: '11px', background: '#111120', border: '1px solid #1a1a2e', borderRadius: '4px', padding: '2px 8px', color: '#aaa' }}>
              Confidence: {Math.round((result.confidence || 0.85) * 100)}%
            </span>
            {result.evidence_source && (
              <span style={{ fontSize: '10px', background: '#1e1b4b', border: '1px solid #3730a3', borderRadius: '4px', padding: '2px 8px', color: '#a5b4fc', fontWeight: 600 }}>
                SRC: {result.evidence_source}
              </span>
            )}
          </div>

          <div style={{ fontSize: '20px', fontWeight: 800, color: cfg.color, marginBottom: '4px', letterSpacing: '0.5px' }}>
            VERDICT: {cfg.label}
          </div>

          <div style={{ fontSize: '12px', color: '#94a3b8', fontFamily: 'DM Mono, monospace', wordBreak: 'break-all', marginBottom: '10px' }}>
            {result.url}
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {verdictLabel !== 'LEGITIMATE' && verdictLabel !== 'LEGIT' && (
              <button onClick={onOpenPreview} style={{
                background: '#1a1a2e', border: '1px solid #333', borderRadius: '6px',
                padding: '6px 12px', fontSize: '12px', color: '#e8e8f0', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '6px',
              }}>
                <Eye size={13} color="#fbbf24" /> Safe Preview Mode
              </button>
            )}
            <button onClick={() => setShowFeedback(true)} style={{
              background: '#111120', border: '1px solid #222', borderRadius: '6px',
              padding: '6px 12px', fontSize: '12px', color: '#aaa', cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '6px',
            }}>
              <ThumbsUp size={12} /> Submit Feedback
            </button>
          </div>
        </div>
      </div>

      {/* ── 4. REDIRECT CHAIN INSPECTOR ── */}
      {redirectInfo && (
        <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem', marginBottom: '1rem' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#38bdf8', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <CornerDownRight size={15} /> Redirect Chain & Navigation Inspection
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <span style={{
                fontSize: '10px', padding: '2px 8px', borderRadius: '4px', fontWeight: 700,
                background: redirectInfo.is_cross_domain ? '#451010' : '#0a2d16',
                color: redirectInfo.is_cross_domain ? '#f87171' : '#4ade80',
                border: `1px solid ${redirectInfo.is_cross_domain ? '#7f1d1d' : '#1a5a30'}`
              }}>
                {redirectInfo.is_cross_domain ? '⚠️ CROSS-DOMAIN REDIRECT' : '✓ SAME-ORIGIN / DIRECT'}
              </span>
              <span style={{ fontSize: '10px', background: '#1e293b', color: '#cbd5e1', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                {redirectInfo.hops || 0} HOPS
              </span>
            </div>
          </div>

          {redirectInfo.chain && redirectInfo.chain.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {redirectInfo.chain.map((step, idx) => (
                <div key={idx} style={{
                  background: '#0a0a12', border: '1px solid #1e293b', borderRadius: '8px', padding: '8px 12px',
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', fontSize: '11px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', overflow: 'hidden' }}>
                    <span style={{ color: '#818cf8', fontWeight: 700, fontFamily: 'monospace' }}>Hop {step.hop}:</span>
                    <span style={{ color: '#e2e8f0', fontFamily: 'monospace', wordBreak: 'break-all' }}>{step.url}</span>
                  </div>
                  <span style={{
                    fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
                    background: step.status >= 300 && step.status < 400 ? '#2a1f00' : '#0a2d16',
                    color: step.status >= 300 && step.status < 400 ? '#fbbf24' : '#4ade80',
                    fontFamily: 'monospace', flexShrink: 0
                  }}>
                    HTTP {step.status}
                  </span>
                </div>
              ))}
              {redirectInfo.final_url && redirectInfo.final_url !== result.url && (
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px', paddingLeft: '4px' }}>
                  Final Destination: <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{redirectInfo.final_url}</span>
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: '11px', color: '#94a3b8', background: '#0a0a12', padding: '10px 12px', borderRadius: '8px', border: '1px solid #1e293b' }}>
              ✓ Direct navigation to destination (No intermediary redirect cloaking detected).
            </div>
          )}
        </div>
      )}

      {/* ── 5. TRUSTED DOMAIN INTELLIGENCE CARD ── */}
      {tda && (
        <div style={{
          background: tda.is_trusted ? 'rgba(16, 185, 129, 0.08)' : (tda.match_level && tda.match_level.includes('IMPERSONATION') ? 'rgba(239, 68, 68, 0.12)' : '#0f0f1a'),
          border: `1px solid ${tda.is_trusted ? '#059669' : (tda.match_level && tda.match_level.includes('IMPERSONATION') ? '#dc2626' : '#1a1a2e')}`,
          borderRadius: '12px', padding: '1.2rem', marginBottom: '1rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', marginBottom: '0.8rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {tda.is_trusted ? (
                <ShieldCheck size={18} color="#10b981" />
              ) : (tda.match_level && tda.match_level.includes('IMPERSONATION')) ? (
                <ShieldAlert size={18} color="#f87171" />
              ) : (
                <Shield size={18} color="#94a3b8" />
              )}
              <span style={{ fontSize: '13px', fontWeight: 700, color: tda.is_trusted ? '#34d399' : ((tda.match_level && tda.match_level.includes('IMPERSONATION')) ? '#f87171' : '#cbd5e1') }}>
                Trusted Domain Intelligence & Knowledge Base
              </span>
            </div>

            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {tda.brand_name && (
                <span style={{
                  fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
                  background: tda.is_trusted ? '#064e3b' : '#451010',
                  color: tda.is_trusted ? '#a7f3d0' : '#fca5a5',
                  border: `1px solid ${tda.is_trusted ? '#047857' : '#7f1d1d'}`
                }}>
                  {tda.brand_name} {tda.service_name && tda.service_name !== tda.brand_name ? `(${tda.service_name})` : ''}
                </span>
              )}

              <span style={{
                fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
                background: tda.is_trusted ? '#042f2e' : '#1e1b4b',
                color: tda.is_trusted ? '#5eead4' : '#c7d2fe',
                border: `1px solid ${tda.is_trusted ? '#115e59' : '#3730a3'}`
              }}>
                {tda.match_level} ({tda.match_score > 0 ? `+${tda.match_score}` : tda.match_score})
              </span>

              {tda.category && (
                <span style={{ fontSize: '11px', background: '#1e293b', color: '#94a3b8', padding: '2px 8px', borderRadius: '4px' }}>
                  {tda.category}
                </span>
              )}

              {tda.is_hosting_provider && (
                <span style={{ fontSize: '11px', background: '#3b2505', color: '#fcd34d', border: '1px solid #78350f', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                  ⚠️ Multi-Tenant Host
                </span>
              )}
            </div>
          </div>

          {/* Registrable domain & verification info */}
          <div style={{
            background: '#0a0a12', borderRadius: '8px', border: '1px solid #1e293b', padding: '8px 12px',
            marginBottom: '0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', fontSize: '11px'
          }}>
            <div>
              <span style={{ color: '#64748b' }}>Public Suffix Root (PSL): </span>
              <span style={{ color: '#e2e8f0', fontFamily: 'monospace', fontWeight: 700 }}>
                {tda.registrable_domain || 'N/A'}
              </span>
            </div>
            <div>
              <span style={{ color: '#64748b' }}>Status: </span>
              <span style={{ color: tda.is_trusted ? '#4ade80' : '#fbbf24', fontWeight: 600 }}>
                {tda.status || 'UNVERIFIED'}
              </span>
            </div>
          </div>

          {/* Verified Reasons List */}
          {tda.reasons && tda.reasons.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              {tda.reasons.map((r, i) => (
                <div key={i} style={{
                  fontSize: '11px', display: 'flex', alignItems: 'flex-start', gap: '6px',
                  color: r.startsWith('✓') ? '#a7f3d0' : (r.startsWith('⚠️') ? '#fca5a5' : '#cbd5e1')
                }}>
                  <span>{r}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── 6. THREAT FINGERPRINT & IDENTIFIER ── */}
      <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem', marginBottom: '1rem' }}>
        <div style={{ fontSize: '12px', fontWeight: 600, color: '#c084fc', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Fingerprint size={15} /> Threat Fingerprint & On-Chain Identifier
          </div>
          <span style={{ fontSize: '10px', background: '#2e1065', color: '#e9d5ff', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
            SHA-256
          </span>
        </div>
        <div style={{
          background: '#0a0a12', border: '1px solid #1e293b', borderRadius: '8px', padding: '10px 14px',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px'
        }}>
          <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#c084fc', wordBreak: 'break-all' }}>
            {fingerprint || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
          </span>
          <button
            onClick={() => {
              if (fingerprint) {
                navigator.clipboard.writeText(fingerprint)
                setCopiedFp(true)
                setTimeout(() => setCopiedFp(false), 2000)
              }
            }}
            style={{
              background: '#1e1b4b', border: '1px solid #3730a3', borderRadius: '6px',
              padding: '5px 10px', fontSize: '11px', color: '#e0e7ff', cursor: 'pointer', flexShrink: 0,
              display: 'flex', alignItems: 'center', gap: '4px'
            }}
          >
            <Copy size={11} /> {copiedFp ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>

      {/* ── 6. UNIFIED EVIDENCE DECOMPOSITION ── */}
      {evidenceList.length > 0 && (
        <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem', marginBottom: '1rem' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#f87171', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={15} /> Multi-Source Evidence & Explainable Reasoning
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {evidenceList.map((item, idx) => {
              const impact = (item.impact || 'MEDIUM').toUpperCase()
              const isBenign = impact === 'BENIGN'
              const isCritical = impact === 'CRITICAL'
              const isHigh = impact === 'HIGH'
              const impactColor = isBenign ? '#4ade80' : isCritical ? '#ef4444' : isHigh ? '#f87171' : '#fbbf24'
              const impactBg = isBenign ? '#0a2d16' : isCritical ? '#451010' : isHigh ? '#3d1212' : '#2a2200'

              return (
                <div key={idx} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '8px 12px', background: '#0a0a12', borderRadius: '8px', border: '1px solid #1e293b',
                  fontSize: '12px', gap: '10px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: isBenign ? '#a7f3d0' : '#e2e8f0' }}>
                    <span style={{ color: impactColor }}>{isBenign ? '✓' : '•'}</span>
                    <span>{item.factor}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
                    {item.source && (
                      <span style={{ fontSize: '9px', fontWeight: 700, padding: '2px 5px', borderRadius: '3px', background: '#1e293b', color: '#94a3b8' }}>
                        {item.source}
                      </span>
                    )}
                    <span style={{
                      fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
                      background: impactBg, color: impactColor,
                    }}>
                      {impact}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── 7. RISK BREAKDOWN ── */}
      <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem', marginBottom: '1rem' }}>
        <div style={{ fontSize: '12px', fontWeight: 600, color: '#818cf8', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <TrendingUp size={14} /> Unified Risk Signal Decomposition
        </div>
        <RiskBar value={rb.url_risk ?? result.threat_score ?? 0} label="URL Lexical & Structural Risk (35%)" />
        <RiskBar value={rb.webpage_risk ?? 0} label="Webpage DOM & Form Risk (25%)" />
        <RiskBar value={rb.behavior_risk ?? 0} label="Behavioral Anomaly Risk (20%)" />
        <RiskBar value={rb.threat_intel_score ?? (isKnownThreat ? 100 : 0)} label="Threat Intelligence & Similarity (15%)" color="#60a5fa" />
        <RiskBar value={rb.ai_deception_score ?? 0} label="AI/Deception Likelihood Indicator (5%)" color="#c084fc" />

        {(rb.ai_deception_score ?? 0) > 0 && (
          <div style={{
            background: '#1a1525', border: '1px solid #3a2a5a', borderRadius: '6px',
            padding: '8px 12px', marginTop: '8px', fontSize: '11px', color: '#a78bfa',
            display: 'flex', gap: '8px',
          }}>
            <Info size={13} style={{ flexShrink: 0, marginTop: 1 }} />
            <span>AI/Deception Risk is an empirical likelihood score based on measurable structural signals. It does not represent absolute proof of AI generation.</span>
          </div>
        )}
      </div>

      {/* ── 8. THREAT INTEL & BLOCKCHAIN RECORD ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
        <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#34d399', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Database size={13} /> Threat Intelligence Status
          </div>
          <div style={{ fontSize: '12px', fontWeight: 600, color: isKnownThreat || intel.previously_detected ? '#f87171' : '#4ade80', marginBottom: '4px' }}>
            {isKnownThreat
              ? `⚠ Active Match: ${tim.source} (${tim.threat_type || 'Malicious'})`
              : intel.previously_detected
              ? `⚠ Previously Detected (${intel.prior_detection_count} reports)`
              : '✓ Clean — No Active Match in Threat Feeds'}
          </div>
          <div style={{ fontSize: '10px', color: '#64748b', marginTop: '4px' }}>
            Sources: OpenPhish • URLhaus • PhishTank • On-Chain Logs
          </div>
        </div>

        <div style={{ background: '#0f0f1a', border: '1px solid #1a1a2e', borderRadius: '12px', padding: '1.2rem' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#60a5fa', marginBottom: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Link2 size={13} /> Blockchain Threat Record
          </div>
          {result.logged_to_blockchain ? (
            <div>
              <div style={{ fontSize: '12px', color: '#4ade80', marginBottom: '4px' }}>✓ Tamper-evident on-chain record confirmed</div>
              <div style={{ fontSize: '10px', color: '#64748b', fontFamily: 'DM Mono, monospace', wordBreak: 'break-all' }}>
                Hash: {result.block_hash ? result.block_hash.slice(0, 24) + '...' : 'Recorded'}
              </div>
            </div>
          ) : (
            <div style={{ fontSize: '12px', color: '#64748b' }}>
              {verdictLabel === 'LEGITIMATE' || verdictLabel === 'LEGIT' ? 'No threat to record (Legitimate)' : 'Mining threshold not reached'}
            </div>
          )}
        </div>
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

  const { snapshot } = useBehaviorTracker('scan', { snapshotInterval: 2500 })

  const handleUrlScan = async (e) => {
    e?.preventDefault()
    if (!urlInput.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const bFeatures = snapshot ? {
        frontend_anomaly_score: snapshot.anomalyScore || 0,
        paste_count: snapshot.pasteCount || 0,
        rapid_clicks: snapshot.rapidClicks || 0,
      } : null
      const data = await scanUrl(urlInput.trim(), bFeatures)
      if (data) setResult({ ...data, input_type: 'URL' })
      else setError('Scan failed. Please verify the URL.')
    } catch {
      setError('Service unavailable. Please retry.')
    } finally {
      setLoading(false)
    }
  }

  const handleQrDecoded = async (decodedUrl) => {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await scanQr(decodedUrl)
      if (data) setResult({ ...data, input_type: 'QR', qr_decoded_url: decodedUrl })
      else setError('QR analysis failed.')
    } catch {
      setError('Service error during QR analysis.')
    } finally {
      setLoading(false)
    }
  }

  const handleWebsiteScan = async (e) => {
    e?.preventDefault()
    if (!urlInput.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const data = await analyzeWebsite(urlInput.trim())
      if (data) setResult({ ...data, input_type: 'WEBSITE' })
      else setError('Website analysis failed.')
    } catch {
      setError('Service unavailable.')
    } finally {
      setLoading(false)
    }
  }

  // Adaptive Real-Time Risk Update (Section 14)
  useEffect(() => {
    if (result && snapshot && snapshot.anomalyScore > 40 && result.label === 'LEGIT') {
      setResult(prev => ({
        ...prev,
        label: 'SUSPICIOUS',
        threat_score: Math.min(100, prev.threat_score + 35),
        risk_breakdown: {
          ...prev.risk_breakdown,
          behavior_risk: snapshot.anomalyScore,
        },
        flags: [...(prev.flags || []), 'Adaptive real-time behavioral anomaly trigger']
      }))
    }
  }, [snapshot, result])

  return (
    <div style={{ minHeight: 'calc(100vh - 60px)', background: '#0a0a0f', padding: '2rem 1rem', fontFamily: 'DM Sans, sans-serif' }}>
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

      <div style={{ maxWidth: '780px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: '8px',
            background: '#1a1a2e', border: '1px solid #2a2a40', borderRadius: '999px',
            padding: '5px 14px', marginBottom: '1rem', fontSize: '11px', color: '#818cf8',
          }}>
            <Shield size={12} /> Domain-Independent Multi-Input Threat Engine
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: '#e8e8f0', margin: '0 0 6px' }}>
            Unified Threat Scanner
          </h1>
          <p style={{ fontSize: '13px', color: '#666', margin: '0 0 12px' }}>
            Analyze URLs, QR codes, or websites before trusting them
          </p>
          {isAuthenticated ? (
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: '8px',
              background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)',
              borderRadius: '8px', padding: '6px 14px', fontSize: '12px', color: '#34d399',
            }}>
              <CheckCircle2 size={14} />
              <span>Signed in as <strong>{user?.email}</strong> — Scans automatically recorded to your personal history.</span>
            </div>
          ) : (
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: '8px',
              background: 'rgba(99, 102, 241, 0.08)', border: '1px solid rgba(99, 102, 241, 0.25)',
              borderRadius: '8px', padding: '6px 14px', fontSize: '12px', color: '#a5b4fc',
            }}>
              <Shield size={14} />
              <span>
                Guest mode active.{' '}
                <button
                  onClick={openAuthModal}
                  style={{
                    background: 'transparent', border: 'none', color: '#38bdf8',
                    textDecoration: 'underline', cursor: 'pointer', fontWeight: 600, padding: 0,
                  }}
                >
                  Sign in
                </button>{' '}
                to retain your scan audit logs and receive security alerts.
              </span>
            </div>
          )}
        </div>

        {/* Tab Selector */}
        <div style={{
          display: 'flex', gap: '4px', background: '#0f0f1a', border: '1px solid #1a1a2e',
          borderRadius: '12px', padding: '4px', marginBottom: '1.5rem',
        }}>
          {TABS.map(({ key, label, icon: Icon }) => (
            <button key={key} onClick={() => { setActiveTab(key); setResult(null); setError(null); setUrlInput('') }}
              style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                padding: '10px 12px', borderRadius: '8px', border: 'none', cursor: 'pointer',
                fontSize: '13px', fontWeight: activeTab === key ? 600 : 400,
                background: activeTab === key ? '#1e1e3a' : 'transparent',
                color: activeTab === key ? '#818cf8' : '#666',
              }}>
              <Icon size={14} /> {label}
            </button>
          ))}
        </div>

        {/* URL Mode */}
        {activeTab === 'url' && (
          <form onSubmit={handleUrlScan} style={{ display: 'flex', gap: '8px' }}>
            <input
              type="text" value={urlInput} onChange={e => setUrlInput(e.target.value)}
              placeholder="Enter URL to inspect (e.g. https://portal-verification-auth.com)"
              required
              style={{
                flex: 1, padding: '12px 14px', borderRadius: '10px', background: '#0f0f1a',
                border: '1px solid #1a1a2e', color: '#e8e8f0', fontSize: '14px',
                fontFamily: 'DM Mono, monospace', outline: 'none',
              }}
            />
            <button type="submit" disabled={loading || !urlInput.trim()} style={{
              padding: '12px 22px', borderRadius: '10px', background: loading ? '#3a3a6e' : '#6366f1',
              color: '#fff', border: 'none', fontWeight: 600, cursor: loading ? 'wait' : 'pointer',
              display: 'flex', alignItems: 'center', gap: '6px',
            }}>
              {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <ScanLine size={16} />}
              {loading ? 'Analyzing...' : 'Scan URL'}
            </button>
          </form>
        )}

        {/* QR Mode */}
        {activeTab === 'qr' && (
          <div>
            <QrScanner onDecoded={handleQrDecoded} />
            <div style={{
              background: '#1a150a', border: '1px solid #3a2a00', borderRadius: '8px',
              padding: '10px 14px', fontSize: '11px', color: '#fbbf24', display: 'flex', gap: '8px',
            }}>
              <Lock size={12} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>PhishSense safe QR scanning policy: Decoded destinations are never visited automatically. Safe preview mode is enforced.</span>
            </div>
          </div>
        )}

        {/* Website Mode */}
        {activeTab === 'website' && (
          <form onSubmit={handleWebsiteScan} style={{ display: 'flex', gap: '8px' }}>
            <input
              type="text" value={urlInput} onChange={e => setUrlInput(e.target.value)}
              placeholder="https://example-site.com"
              required
              style={{
                flex: 1, padding: '12px 14px', borderRadius: '10px', background: '#0f0f1a',
                border: '1px solid #1a1a2e', color: '#e8e8f0', fontSize: '14px',
                fontFamily: 'DM Mono, monospace', outline: 'none',
              }}
            />
            <button type="submit" disabled={loading || !urlInput.trim()} style={{
              padding: '12px 22px', borderRadius: '10px', background: loading ? '#3a3a6e' : '#6366f1',
              color: '#fff', border: 'none', fontWeight: 600, cursor: loading ? 'wait' : 'pointer',
              display: 'flex', alignItems: 'center', gap: '6px',
            }}>
              {loading ? <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> : <Globe size={16} />}
              {loading ? 'Analyzing...' : 'Analyze Website'}
            </button>
          </form>
        )}

        {loading && (
          <div style={{ textAlign: 'center', padding: '3rem 2rem' }}>
            <Loader2 size={32} color="#6366f1" style={{ animation: 'spin 1s linear infinite', margin: '0 auto 1rem', display: 'block' }} />
            <div style={{ fontSize: '14px', fontWeight: 600, color: '#e8e8f0' }}>Running multi-input threat pipeline...</div>
            <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>AI inference · DOM extraction · Campaign similarity · Blockchain lookup</div>
          </div>
        )}

        {error && (
          <div style={{
            marginTop: '1rem', background: '#2d0a0a', border: '1px solid #5a1515',
            borderRadius: '10px', padding: '1rem', color: '#f87171', fontSize: '13px',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            <AlertTriangle size={16} /> {error}
          </div>
        )}

        {!loading && result && (
          <ResultPanel
            result={result}
            inputType={result.input_type || activeTab.toUpperCase()}
            onOpenPreview={() => setSafePreviewUrl(result.url)}
          />
        )}

        {/* Live Interaction HUD Note */}
        {snapshot && (
          <div style={{
            marginTop: '1.5rem', background: '#0f0f1a', border: '1px solid #1a1a2e',
            borderRadius: '8px', padding: '8px 14px', display: 'flex', alignItems: 'center',
            gap: '8px', fontSize: '11px', color: '#666',
          }}>
            <Activity size={12} color="#818cf8" />
            <span>Real-time behavioral telemetry: Anomaly Index <strong style={{ color: '#818cf8' }}>{snapshot.anomalyScore}</strong> | Keystrokes: {snapshot.keystrokes?.length || 0} | Clicks: {snapshot.clicks?.length || 0}</span>
          </div>
        )}
      </div>
    </div>
  )
}
