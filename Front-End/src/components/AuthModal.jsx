import React, { useState, useEffect, useRef } from 'react'
import { useAuth } from '../context/AuthContext'
import { requestOtp, verifyOtp } from '../utils/api'
import { Shield, Mail, AlertCircle, CheckCircle2, ArrowRight, RefreshCw, X, KeyRound, Check } from 'lucide-react'

export default function AuthModal() {
  const { isAuthModalOpen, closeAuthModal, loginWithToken } = useAuth()

  const [mode, setMode] = useState('EMAIL_ENTER') // 'EMAIL_ENTER' | 'OTP_VERIFY'
  const [email, setEmail] = useState('')
  const [otp, setOtp] = useState(['', '', '', '', '', ''])
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)
  const [cooldown, setCooldown] = useState(0)

  const otpInputsRef = useRef([])

  useEffect(() => {
    if (cooldown <= 0) return
    const timer = setInterval(() => {
      setCooldown((c) => Math.max(0, c - 1))
    }, 1000)
    return () => clearInterval(timer)
  }, [cooldown])

  useEffect(() => {
    if (isAuthModalOpen) {
      setMode('EMAIL_ENTER')
      setEmail('')
      setOtp(['', '', '', '', '', ''])
      setError('')
      setInfo('')
      setLoading(false)
    }
  }, [isAuthModalOpen])

  if (!isAuthModalOpen) return null

  const handleRequestOtp = async (e) => {
    if (e) e.preventDefault()
    setError('')
    setInfo('')

    if (!email || !email.includes('@')) {
      setError('Please provide a valid email address.')
      return
    }

    setLoading(true)
    try {
      const res = await requestOtp(email.trim().toLowerCase())
      if (res && res.error) {
        setError(res.error)
      } else if (res && res.success) {
        setInfo(res.message || `Code sent to ${email}`)
        setMode('OTP_VERIFY')
        setCooldown(60)
        setOtp(['', '', '', '', '', ''])
        setTimeout(() => {
          if (otpInputsRef.current[0]) otpInputsRef.current[0].focus()
        }, 150)
      } else {
        setError('Failed to send verification code. Please retry.')
      }
    } catch (err) {
      setError(err.message || 'Unable to reach backend server.')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyOtp = async (e) => {
    if (e) e.preventDefault()
    const fullOtp = otp.join('')
    if (fullOtp.length !== 6) {
      setError('Please enter the full 6-digit code.')
      return
    }

    setError('')
    setLoading(true)
    try {
      const res = await verifyOtp(email.trim().toLowerCase(), fullOtp)
      if (res && res.error) {
        setError(res.error)
      } else if (res && res.token && res.user) {
        setInfo('Authenticated successfully!')
        loginWithToken(res.token, res.user)
        setTimeout(() => closeAuthModal(), 400)
      } else {
        setError('Invalid or expired code.')
      }
    } catch (err) {
      setError(err.message || 'Verification failed. Please retry.')
    } finally {
      setLoading(false)
    }
  }

  const handleOtpChange = (index, value) => {
    const clean = value.replace(/\D/g, '')
    if (clean.length > 1) {
      const digits = clean.slice(0, 6).split('')
      const updated = [...otp]
      digits.forEach((d, i) => {
        if (index + i < 6) updated[index + i] = d
      })
      setOtp(updated)
      const nextIndex = Math.min(5, index + digits.length)
      if (otpInputsRef.current[nextIndex]) otpInputsRef.current[nextIndex].focus()
      return
    }

    const updated = [...otp]
    updated[index] = clean
    setOtp(updated)

    if (clean && index < 5) {
      otpInputsRef.current[index + 1]?.focus()
    }
  }

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpInputsRef.current[index - 1]?.focus()
    }
  }

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.75)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '16px',
      zIndex: 9999,
      fontFamily: 'DM Sans, sans-serif',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '430px',
        background: '#0d111e',
        border: '1px solid #1f2a42',
        borderRadius: '18px',
        boxShadow: '0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(99,102,241,0.15)',
        overflow: 'hidden',
        position: 'relative',
      }}>
        <button
          type="button"
          onClick={closeAuthModal}
          style={{
            position: 'absolute', right: '16px', top: '16px',
            background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '6px',
          }}
        >
          <X size={18} />
        </button>

        <div style={{ padding: '28px 24px 20px', textAlign: 'center', borderBottom: '1px solid #162035' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: '46px', height: '46px', borderRadius: '12px',
            background: 'linear-gradient(135deg, #6366f1, #3b82f6)', marginBottom: '12px',
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <h3 style={{ margin: '0 0 6px', color: '#f8fafc', fontSize: '19px', fontWeight: 700 }}>
            Sign In with Email OTP
          </h3>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '13px' }}>
            Enter your email to receive a 6-digit login code
          </p>
        </div>

        <div style={{ padding: '22px 24px 28px' }}>
          {error && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '8px', padding: '10px 12px', marginBottom: '16px',
              color: '#fca5a5', fontSize: '12.5px',
            }}>
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {info && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: '8px',
              background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: '8px', padding: '10px 12px', marginBottom: '16px',
              color: '#34d399', fontSize: '12.5px',
            }}>
              <CheckCircle2 size={15} style={{ flexShrink: 0 }} />
              <span>{info}</span>
            </div>
          )}

          {mode === 'EMAIL_ENTER' && (
            <form onSubmit={handleRequestOtp}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '12.5px', color: '#94a3b8', marginBottom: '6px' }}>
                  Email address
                </label>
                <div style={{ position: 'relative' }}>
                  <Mail size={16} color="#64748b" style={{ position: 'absolute', left: '12px', top: '14px' }} />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@example.com"
                    style={{
                      width: '100%',
                      padding: '11px 12px 11px 38px',
                      background: '#131b2e',
                      border: '1px solid #283754',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '14px',
                      outline: 'none',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '11px',
                  borderRadius: '8px',
                  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
                  border: 'none',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 600,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  cursor: loading ? 'not-allowed' : 'pointer',
                }}
              >
                {loading ? <RefreshCw size={16} className="animate-spin" /> : <span>Send OTP</span>}
              </button>
            </form>
          )}

          {mode === 'OTP_VERIFY' && (
            <form onSubmit={handleVerifyOtp}>
              <div style={{ textAlign: 'center', marginBottom: '16px' }}>
                <KeyRound size={22} color="#818cf8" style={{ marginBottom: '6px' }} />
                <p style={{ margin: 0, color: '#94a3b8', fontSize: '12.5px' }}>
                  Enter code sent to <span style={{ color: '#818cf8' }}>{email}</span>
                </p>
              </div>

              <div style={{ display: 'flex', gap: '6px', justifyContent: 'center', marginBottom: '18px' }}>
                {otp.map((d, i) => (
                  <input
                    key={i}
                    ref={(el) => (otpInputsRef.current[i] = el)}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={d}
                    onChange={(e) => handleOtpChange(i, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(i, e)}
                    style={{
                      width: '42px', height: '48px', textAlign: 'center', fontSize: '20px',
                      fontWeight: 700, background: '#131b2e', border: d ? '2px solid #6366f1' : '1px solid #283754',
                      borderRadius: '8px', color: '#f8fafc', outline: 'none',
                    }}
                  />
                ))}
              </div>

              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '11px',
                  borderRadius: '8px',
                  background: 'linear-gradient(135deg, #10b981, #059669)',
                  border: 'none',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 600,
                  cursor: loading ? 'not-allowed' : 'pointer',
                }}
              >
                {loading ? <RefreshCw size={16} className="animate-spin" /> : <span>Verify & Sign In</span>}
              </button>

              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px', fontSize: '12px' }}>
                <button
                  type="button"
                  onClick={() => setMode('EMAIL_ENTER')}
                  style={{ background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer' }}
                >
                  ← Back
                </button>
                <button
                  type="button"
                  disabled={cooldown > 0 || loading}
                  onClick={handleRequestOtp}
                  style={{
                    background: 'transparent', border: 'none',
                    color: cooldown > 0 ? '#475569' : '#818cf8', cursor: cooldown > 0 ? 'default' : 'pointer',
                  }}
                >
                  {cooldown > 0 ? `Resend (${cooldown}s)` : 'Resend'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
