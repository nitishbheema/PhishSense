import { useState } from 'react'
import { AlertTriangle, Shield, X, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'
import { useBehaviorTracker } from '../hooks/useBehaviorTracker'
import BehaviorHUD from '../components/BehaviorHUD'
import { analyzeBehavior } from '../utils/api'

export default function PhishingLogin() {
  const [dismissed, setDismissed] = useState(false)
  const [showWarning, setShowWarning] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [finalSnap, setFinalSnap] = useState(null)

  const { snapshot, stopAndGet } = useBehaviorTracker('phishing-demo', {
    snapshotInterval: 1000,
    anomalyThreshold: 40,
    onAnomaly: (snap) => {
      console.warn('[PhishGuard] Anomaly on phishing page:', snap.flags)
    }
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    const snap = stopAndGet()
    setFinalSnap(snap)
    analyzeBehavior(snap).then(r => console.log('[PhishGuard] Analysis:', r))
    setShowWarning(true)
  }

  return (
    <div style={{
      minHeight: '100vh', background: '#f8fafc',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'DM Sans, sans-serif', position: 'relative',
    }}>

      {!dismissed && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, zIndex: 999,
          background: '#dc2626', color: '#fff',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 1.5rem', fontSize: '13px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={16} />
            <strong>PhishGuard Alert:</strong> Simulated phishing page — behavioral tracking is LIVE.
          </div>
          <button onClick={() => setDismissed(true)} style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>
      )}

      <div style={{
        background: '#fff', borderRadius: '16px',
        boxShadow: '0 4px 40px rgba(0,0,0,0.08)',
        padding: '2.5rem', width: '100%', maxWidth: '420px',
        margin: !dismissed ? '4rem 1rem 1rem' : '1rem',
        border: '2px solid #dc2626', position: 'relative',
      }}>
        <div style={{
          position: 'absolute', top: '-12px', left: '50%', transform: 'translateX(-50%)',
          background: '#dc2626', borderRadius: '999px', padding: '3px 12px',
          fontSize: '11px', color: '#fff', fontWeight: 700, whiteSpace: 'nowrap',
        }}>
          PHISHING PAGE SIMULATION
        </div>

        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            width: '52px', height: '52px', borderRadius: '14px',
            background: '#6366f1', display: 'flex', alignItems: 'center',
            justifyContent: 'center', margin: '0 auto 1rem',
          }}>
            <Shield size={26} color="#fff" />
          </div>
          <div style={{
            background: '#fef2f2', border: '1px solid #fecaca',
            borderRadius: '6px', padding: '5px 10px', marginBottom: '10px',
            fontSize: '12px', color: '#dc2626', fontFamily: 'DM Mono, monospace',
          }}>
            secure-porta1.verify-login.com
          </div>
          <h1 style={{ fontSize: '22px', fontWeight: 700, color: '#0f172a', margin: '0 0 6px', letterSpacing: '-0.5px' }}>
            SecurePortal
          </h1>
          <p style={{ fontSize: '14px', color: '#94a3b8', margin: 0 }}>Sign in to your account</p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#374151', marginBottom: '6px' }}>
              Email Address
            </label>
            <input
              type="email" required name="email"
              value={email} onChange={e => setEmail(e.target.value)}
              placeholder="you@example.com"
              style={{
                width: '100%', padding: '10px 14px', borderRadius: '8px',
                border: '1px solid #e2e8f0', fontSize: '14px', color: '#0f172a',
                outline: 'none', fontFamily: 'DM Sans, sans-serif', boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, color: '#374151', marginBottom: '6px' }}>
              Password
            </label>
            <input
              type="password" required name="password"
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="Enter your password"
              style={{
                width: '100%', padding: '10px 14px', borderRadius: '8px',
                border: '1px solid #e2e8f0', fontSize: '14px', color: '#0f172a',
                outline: 'none', fontFamily: 'DM Sans, sans-serif', boxSizing: 'border-box',
              }}
            />
          </div>

          <button type="submit" style={{
            width: '100%', padding: '11px', borderRadius: '8px',
            background: '#6366f1', color: '#fff', fontWeight: 600, fontSize: '15px',
            border: 'none', cursor: 'pointer', fontFamily: 'DM Sans, sans-serif',
          }}>
            Sign In
          </button>
        </form>
      </div>

      {showWarning && finalSnap && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 9999, padding: '1rem',
        }}>
          <div style={{
            background: '#fff', borderRadius: '16px', padding: '2rem',
            maxWidth: '440px', width: '100%',
          }}>
            <div style={{ textAlign: 'center', marginBottom: '1.2rem' }}>
              <div style={{
                width: '60px', height: '60px', borderRadius: '50%',
                background: '#fef2f2', display: 'flex', alignItems: 'center',
                justifyContent: 'center', margin: '0 auto 1rem',
              }}>
                <AlertTriangle size={30} color="#dc2626" />
              </div>
              <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#0f172a', margin: '0 0 8px' }}>
                Phishing Detected!
              </h2>
              <p style={{ fontSize: '14px', color: '#64748b', lineHeight: 1.6, margin: 0 }}>
                Behavioral AI caught this. No real data was sent — this is a controlled demo.
              </p>
            </div>

            {/* Behavioral summary */}
            <div style={{
              background: '#f8fafc', borderRadius: '10px', padding: '1rem',
              marginBottom: '1rem', fontSize: '13px',
            }}>
              <div style={{ fontWeight: 600, marginBottom: '8px', color: '#374151' }}>
                Behavior Captured:
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                {[
                  ['Anomaly Score', `${finalSnap.anomalyScore}%`],
                  ['Keystrokes', finalSnap.keystrokes.length],
                  ['Mouse Points', finalSnap.mousePath.length],
                  ['Pastes', finalSnap.pasteCount],
                  ['Clicks', finalSnap.clicks.length],
                  ['Time on page', `${(finalSnap.totalActiveMs / 1000).toFixed(1)}s`],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: '#fff', borderRadius: '6px', padding: '6px 10px', border: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: '10px', color: '#94a3b8' }}>{k}</div>
                    <div style={{ fontWeight: 600, color: '#0f172a' }}>{v}</div>
                  </div>
                ))}
              </div>

              {finalSnap.flags.length > 0 && (
                <div style={{ marginTop: '10px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: '#dc2626', marginBottom: '4px' }}>Flags:</div>
                  {finalSnap.flags.map((f, i) => (
                    <div key={i} style={{ fontSize: '11px', color: '#dc2626', marginBottom: '2px' }}>
                      ⚠ {f}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <Link to="/dashboard" style={{
                flex: 1, padding: '10px', borderRadius: '8px', background: '#6366f1',
                color: '#fff', textDecoration: 'none', fontWeight: 600, fontSize: '14px',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
              }}>
                Dashboard <ExternalLink size={13} />
              </Link>
              <button onClick={() => setShowWarning(false)} style={{
                flex: 1, padding: '10px', borderRadius: '8px', background: '#f1f5f9',
                color: '#374151', fontWeight: 600, fontSize: '14px', border: 'none', cursor: 'pointer',
              }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <BehaviorHUD snapshot={snapshot} position="bottom-right" />
    </div>
  )
}
