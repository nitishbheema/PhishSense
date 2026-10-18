import React, { useState, useEffect, useRef } from 'react'
import { useAuth } from '../context/AuthContext'
import { requestOtp, verifyOtp } from '../utils/api'
import {
  Shield, Mail, AlertCircle, CheckCircle2, ArrowRight,
  RefreshCw, Lock, Sparkles, Check, KeyRound
} from 'lucide-react'

export default function LoginGate({ children }) {
  const { isAuthenticated, isLoading, loginWithToken } = useAuth()

  const [mode, setMode] = useState('EMAIL_ENTER') // 'EMAIL_ENTER' | 'OTP_VERIFY'
  const [email, setEmail] = useState('')
  const [otp, setOtp] = useState(['', '', '', '', '', ''])
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [cooldown, setCooldown] = useState(0)

  const otpInputsRef = useRef([])

  // Resend countdown timer
  useEffect(() => {
    if (cooldown <= 0) return
    const timer = setInterval(() => {
      setCooldown((c) => Math.max(0, c - 1))
    }, 1000)
    return () => clearInterval(timer)
  }, [cooldown])

  // 1. Loading state while verifying existing session
  if (isLoading) {
    return (
      <div style={{
        minHeight: '100vh',
        background: '#0a0a0f',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: '16px',
        color: '#818cf8',
        fontFamily: 'DM Sans, sans-serif',
      }}>
        <div style={{
          width: '46px',
          height: '46px',
          borderRadius: '50%',
          border: '3px solid #1e1e3a',
          borderTopColor: '#6366f1',
          animation: 'spin 0.8s linear infinite',
        }} />
        <span style={{ fontSize: '14px', color: '#94a3b8', letterSpacing: '0.2px' }}>
          Verifying PhishSense Security Session...
        </span>
      </div>
    )
  }

  // 2. If authenticated, unlock and open the full website!
  if (isAuthenticated) {
    return children
  }

  // 3. Request Real OTP Email (dispatched from hello.aurasync@gmail.com)
  const handleRequestOtp = async (e) => {
    if (e) e.preventDefault()
    setError('')
    setInfo('')

    if (!email || !email.includes('@')) {
      setError('Please enter a valid email address.')
      return
    }

    setSubmitting(true)
    try {
      const res = await requestOtp(email.trim().toLowerCase())
      if (res && res.error) {
        setError(res.error)
      } else if (res && res.success) {
        setInfo(res.message || `Verification code sent to ${email}. Check your inbox and spam folder.`)
        setMode('OTP_VERIFY')
        setCooldown(60)
        setOtp(['', '', '', '', '', ''])
        setTimeout(() => {
          if (otpInputsRef.current[0]) otpInputsRef.current[0].focus()
        }, 150)
      } else {
        setError('Failed to dispatch verification code. Please retry.')
      }
    } catch (err) {
      setError(err.message || 'Unable to reach backend server.')
    } finally {
      setSubmitting(false)
    }
  }

  // 4. Verify OTP Code
  const handleVerifyOtp = async (e) => {
    if (e) e.preventDefault()
    const fullOtp = otp.join('')
    if (fullOtp.length !== 6) {
      setError('Please enter the full 6-digit verification code.')
      return
    }

    setError('')
    setSubmitting(true)
    try {
      const res = await verifyOtp(email.trim().toLowerCase(), fullOtp)
      if (res && res.error) {
        setError(res.error)
      } else if (res && res.token && res.user) {
        setInfo('Verification successful! Unlocking PhishSense...')
        loginWithToken(res.token, res.user)
      } else {
        setError('Invalid or expired verification code.')
      }
    } catch (err) {
      setError(err.message || 'Verification failed. Please retry.')
    } finally {
      setSubmitting(false)
    }
  }

  // 5. Handle OTP Box Changes
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
      minHeight: '100vh',
      background: 'radial-gradient(ellipse at 50% 20%, #151c38 0%, #080c16 65%, #05070c 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1.5rem',
      fontFamily: 'DM Sans, sans-serif',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Background ambient glow */}
      <div style={{
        position: 'absolute',
        top: '15%',
        left: '50%',
        transform: 'translateX(-50%)',
        width: '600px',
        height: '350px',
        background: 'radial-gradient(circle, rgba(99, 102, 241, 0.12) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div style={{
        width: '100%',
        maxWidth: '440px',
        background: 'rgba(13, 17, 30, 0.95)',
        border: '1px solid #1f2a42',
        borderRadius: '20px',
        boxShadow: '0 25px 70px -15px rgba(0, 0, 0, 0.8), 0 0 45px rgba(99, 102, 241, 0.15)',
        backdropFilter: 'blur(16px)',
        overflow: 'hidden',
        position: 'relative',
        zIndex: 1,
      }}>
        {/* Top Header */}
        <div style={{
          padding: '32px 30px 24px',
          textAlign: 'center',
          borderBottom: '1px solid #182238',
        }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '54px',
            height: '54px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, #6366f1 0%, #3b82f6 50%, #06b6d4 100%)',
            boxShadow: '0 8px 24px rgba(99, 102, 241, 0.4)',
            marginBottom: '16px',
          }}>
            <Shield size={28} color="#ffffff" strokeWidth={2.3} />
          </div>

          <h2 style={{
            margin: '0 0 6px',
            fontSize: '23px',
            fontWeight: 700,
            color: '#f8fafc',
            letterSpacing: '-0.3px',
          }}>
            PhishSense Access Portal
          </h2>
          <p style={{
            margin: 0,
            fontSize: '13px',
            color: '#94a3b8',
            lineHeight: 1.5,
          }}>
            Authentication required to access Threat Intelligence Platform
          </p>
        </div>

        {/* Form Body */}
        <div style={{ padding: '26px 30px 32px' }}>
          {/* Error Banner */}
          {error && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: '10px',
              background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.35)',
              borderRadius: '10px', padding: '12px 14px', marginBottom: '20px',
              color: '#fca5a5', fontSize: '13px', lineHeight: 1.45,
            }}>
              <AlertCircle size={17} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>{error}</span>
            </div>
          )}

          {/* Success Banner */}
          {info && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: '10px',
              background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)',
              borderRadius: '10px', padding: '12px 14px', marginBottom: '20px',
              color: '#34d399', fontSize: '13px', lineHeight: 1.45,
            }}>
              <CheckCircle2 size={17} style={{ flexShrink: 0, marginTop: '2px' }} />
              <span>{info}</span>
            </div>
          )}

          {/* STEP 1: ENTER EMAIL */}
          {mode === 'EMAIL_ENTER' && (
            <form onSubmit={handleRequestOtp}>
              <div style={{ marginBottom: '20px' }}>
                <label style={{
                  display: 'block',
                  fontSize: '13px',
                  color: '#94a3b8',
                  marginBottom: '8px',
                  fontWeight: 500,
                }}>
                  Enter your email address
                </label>
                <div style={{ position: 'relative' }}>
                  <Mail
                    size={17}
                    color="#64748b"
                    style={{ position: 'absolute', left: '14px', top: '15px' }}
                  />
                  <input
                    type="email"
                    required
                    autoFocus
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@example.com"
                    style={{
                      width: '100%',
                      padding: '13px 14px 13px 42px',
                      background: '#131b2e',
                      border: '1px solid #283754',
                      borderRadius: '10px',
                      color: '#f8fafc',
                      fontSize: '14.5px',
                      outline: 'none',
                      boxSizing: 'border-box',
                      transition: 'border-color 0.2s',
                    }}
                    onFocus={(e) => e.target.style.borderColor = '#6366f1'}
                    onBlur={(e) => e.target.style.borderColor = '#283754'}
                  />
                </div>
                <div style={{ fontSize: '11.5px', color: '#64748b', marginTop: '6px' }}>
                  A 6-digit verification code will be dispatched to your inbox.
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                style={{
                  width: '100%',
                  padding: '13px',
                  borderRadius: '10px',
                  background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
                  border: 'none',
                  color: '#fff',
                  fontSize: '14.5px',
                  fontWeight: 600,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  cursor: submitting ? 'not-allowed' : 'pointer',
                  opacity: submitting ? 0.75 : 1,
                  boxShadow: '0 4px 16px rgba(99,102,241,0.35)',
                  transition: 'all 0.2s ease',
                }}
              >
                {submitting ? (
                  <>
                    <RefreshCw size={17} className="animate-spin" />
                    <span>Sending Verification Code...</span>
                  </>
                ) : (
                  <>
                    <span>Send Verification Code</span>
                    <ArrowRight size={17} />
                  </>
                )}
              </button>
            </form>
          )}

          {/* STEP 2: ENTER 6-DIGIT OTP */}
          {mode === 'OTP_VERIFY' && (
            <form onSubmit={handleVerifyOtp}>
              <div style={{ textAlign: 'center', marginBottom: '22px' }}>
                <div style={{
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  width: '46px', height: '46px', borderRadius: '50%',
                  background: '#1c1f3d', color: '#818cf8', marginBottom: '12px',
                }}>
                  <KeyRound size={22} />
                </div>
                <h3 style={{ margin: '0 0 6px', color: '#f1f5f9', fontSize: '17px', fontWeight: 600 }}>
                  Enter Verification Code
                </h3>
                <p style={{ margin: 0, color: '#94a3b8', fontSize: '13px' }}>
                  We sent a 6-digit code to <span style={{ color: '#818cf8', fontWeight: 600 }}>{email}</span>
                </p>
                <div style={{ fontSize: '11.5px', color: '#64748b', marginTop: '4px' }}>
                  (Be sure to check your Spam / Junk folder if not in Inbox)
                </div>
              </div>

              {/* 6 Digit Input Boxes */}
              <div style={{
                display: 'flex', gap: '8px', justifyContent: 'center',
                marginBottom: '24px',
              }}>
                {otp.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => (otpInputsRef.current[idx] = el)}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpChange(idx, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(idx, e)}
                    style={{
                      width: '46px',
                      height: '52px',
                      textAlign: 'center',
                      fontSize: '22px',
                      fontWeight: 700,
                      background: '#131b2e',
                      border: digit ? '2px solid #6366f1' : '1px solid #283754',
                      borderRadius: '10px',
                      color: '#f8fafc',
                      outline: 'none',
                      transition: 'border-color 0.15s',
                    }}
                  />
                ))}
              </div>

              <button
                type="submit"
                disabled={submitting}
                style={{
                  width: '100%',
                  padding: '13px',
                  borderRadius: '10px',
                  background: 'linear-gradient(135deg, #10b981, #059669)',
                  border: 'none',
                  color: '#fff',
                  fontSize: '14.5px',
                  fontWeight: 600,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
                  cursor: submitting ? 'not-allowed' : 'pointer',
                  opacity: submitting ? 0.75 : 1,
                  boxShadow: '0 4px 16px rgba(16,185,129,0.35)',
                  transition: 'all 0.2s ease',
                }}
              >
                {submitting ? (
                  <>
                    <RefreshCw size={17} className="animate-spin" />
                    <span>Verifying Code...</span>
                  </>
                ) : (
                  <>
                    <span>Verify Code & Open Website</span>
                    <Check size={17} />
                  </>
                )}
              </button>

              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginTop: '18px',
                paddingTop: '14px',
                borderTop: '1px solid #162035',
              }}>
                <button
                  type="button"
                  onClick={() => setMode('EMAIL_ENTER')}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#64748b',
                    fontSize: '12.5px',
                    cursor: 'pointer',
                  }}
                >
                  ← Change Email
                </button>

                <button
                  type="button"
                  disabled={cooldown > 0 || submitting}
                  onClick={handleRequestOtp}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: cooldown > 0 ? '#475569' : '#818cf8',
                    fontSize: '12.5px',
                    cursor: cooldown > 0 ? 'default' : 'pointer',
                    fontWeight: 500,
                  }}
                >
                  {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend Code'}
                </button>
              </div>
            </form>
          )}

          {/* Footer Security Badges */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '16px',
            marginTop: '26px',
            paddingTop: '20px',
            borderTop: '1px solid #141c2e',
            color: '#64748b',
            fontSize: '11.5px',
          }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Lock size={12} color="#10b981" /> 256-bit TLS
            </span>
            <span>•</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Mail size={12} color="#38bdf8" /> Email OTP
            </span>
            <span>•</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Sparkles size={12} color="#6366f1" /> Blockchain Audit
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}
