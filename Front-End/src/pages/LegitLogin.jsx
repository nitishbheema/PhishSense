import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, CheckCircle2 } from 'lucide-react'
import { useBehaviorTracker } from '../hooks/useBehaviorTracker'
import BehaviorHUD from '../components/BehaviorHUD'
import { analyzeBehavior } from '../utils/api'

export default function LegitLogin() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const navigate = useNavigate()

  const { snapshot, stopAndGet } = useBehaviorTracker('legit-login', {
    snapshotInterval: 1000,
    anomalyThreshold: 60,
    onAnomaly: (snap) => {
      // Anomaly detected on legit page — flagged for research purposes
    }
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    const finalData = stopAndGet()
    analyzeBehavior(finalData)
    setLoading(true)
    setTimeout(() => {
      setLoading(false)
      setSuccess(true)
      setTimeout(() => navigate('/dashboard'), 1500)
    }, 1200)
  }

  return (
    <div style={{
      minHeight: '100vh', background: '#f8fafc',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'DM Sans, sans-serif',
    }}>
      <div style={{
        background: '#fff', borderRadius: '16px',
        boxShadow: '0 4px 40px rgba(0,0,0,0.08)',
        padding: '2.5rem', width: '100%', maxWidth: '420px', margin: '1rem',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            width: '52px', height: '52px', borderRadius: '14px',
            background: '#6366f1', display: 'flex', alignItems: 'center',
            justifyContent: 'center', margin: '0 auto 1rem',
          }}>
            <Shield size={26} color="#fff" />
          </div>
          <h1 style={{ fontSize: '22px', fontWeight: 700, color: '#0f172a', margin: '0 0 6px', letterSpacing: '-0.5px' }}>
            SecurePortal
          </h1>
          <p style={{ fontSize: '14px', color: '#94a3b8', margin: 0 }}>Sign in to your account</p>
        </div>

        <div style={{
          background: '#f0fdf4', border: '1px solid #bbf7d0',
          borderRadius: '8px', padding: '10px 14px',
          display: 'flex', alignItems: 'center', gap: '8px',
          marginBottom: '1.5rem',
        }}>
          <CheckCircle2 size={15} color="#16a34a" />
          <span style={{ fontSize: '12px', color: '#15803d', fontWeight: 500 }}>
            Verified Secure Connection · SSL Certificate Valid
          </span>
        </div>

        {success ? (
          <div style={{ textAlign: 'center', padding: '2rem', background: '#f0fdf4', borderRadius: '10px' }}>
            <CheckCircle2 size={40} color="#16a34a" style={{ margin: '0 auto 12px', display: 'block' }} />
            <p style={{ color: '#16a34a', fontWeight: 600, fontSize: '15px', margin: '0 0 4px' }}>Login Successful!</p>
            <p style={{ color: '#888', fontSize: '13px', margin: 0 }}>Redirecting to dashboard...</p>
          </div>
        ) : (
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
              <div style={{ position: 'relative' }}>
                <input
                  type={showPass ? 'text' : 'password'} required name="password"
                  value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  style={{
                    width: '100%', padding: '10px 42px 10px 14px', borderRadius: '8px',
                    border: '1px solid #e2e8f0', fontSize: '14px', color: '#0f172a',
                    outline: 'none', fontFamily: 'DM Sans, sans-serif', boxSizing: 'border-box',
                  }}
                />
                <button type="button" onClick={() => setShowPass(!showPass)} style={{
                  position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: 0,
                }}>
                  {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button type="submit" disabled={loading} style={{
              width: '100%', padding: '11px', borderRadius: '8px',
              background: loading ? '#a5b4fc' : '#6366f1',
              color: '#fff', fontWeight: 600, fontSize: '15px',
              border: 'none', cursor: loading ? 'wait' : 'pointer',
              fontFamily: 'DM Sans, sans-serif', transition: 'background 0.2s',
            }}>
              {loading ? 'Signing in...' : 'Sign In'}
            </button>

            <p style={{ textAlign: 'center', fontSize: '12px', color: '#94a3b8', marginTop: '1.2rem' }}>
              Legitimate demo portal · Behavioral tracking active
            </p>
          </form>
        )}
      </div>

      {/* Live HUD for demo/research viewing */}
      <BehaviorHUD snapshot={snapshot} position="bottom-right" />
    </div>
  )
}
