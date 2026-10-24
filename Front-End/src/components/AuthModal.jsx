import React, { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { loginWithEmail } from '../utils/api'
import {
  Shield, Mail, AlertCircle, CheckCircle2, ArrowRight,
  RefreshCw, X, Sparkles, User, History, BellRing
} from 'lucide-react'

export default function AuthModal() {
  const { isAuthModalOpen, closeAuthModal, loginWithToken } = useAuth()

  const [identifier, setIdentifier] = useState('')
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isAuthModalOpen) {
      setIdentifier('')
      setError('')
      setInfo('')
      setLoading(false)
    }
  }, [isAuthModalOpen])

  if (!isAuthModalOpen) return null

  const handleSignIn = async (e, customIdentifier = null) => {
    if (e) e.preventDefault()
    setError('')
    setInfo('')

    const target = (customIdentifier || identifier || '').trim()
    if (!target) {
      setError('Please enter a username or email address.')
      return
    }

    setLoading(true)
    try {
      const res = await loginWithEmail(target)
      if (res && res.token && res.user) {
        setInfo(`Welcome, ${res.user.fullName || res.user.email}! Tracking enabled.`)
        loginWithToken(res.token, res.user)
        setTimeout(() => closeAuthModal(), 500)
        return
      }

      if (res && res.error) {
        // Fallback for offline demo mode if backend is not reachable
        if (res.error.includes('backend') || res.error.includes('reach server') || res.error.includes('Failed to fetch')) {
          const fallbackUser = {
            id: 'local-' + Date.now(),
            email: target.includes('@') ? target : `${target}@phishsense.local`,
            fullName: target.includes('@') ? target.split('@')[0] : target,
            avatarUrl: `https://api.dicebear.com/7.x/identicon/svg?seed=${target}`,
            authProvider: 'LOCAL_DEMO',
            emailVerified: true,
          }
          const mockToken = 'mock-jwt-token-' + Date.now()
          setInfo(`Demo Mode: Signed in as ${fallbackUser.fullName}. Tracking active!`)
          loginWithToken(mockToken, fallbackUser)
          setTimeout(() => closeAuthModal(), 500)
          return
        }
        setError(res.error)
      } else {
        setError('Sign in could not be completed. Please try again.')
      }
    } catch (err) {
      setError(err.message || 'Unable to connect to server.')
    } finally {
      setLoading(false)
    }
  }

  const handleQuickPreset = (presetEmail) => {
    setIdentifier(presetEmail)
    handleSignIn(null, presetEmail)
  }

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(5, 7, 15, 0.82)',
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
        maxWidth: '440px',
        background: '#0d111e',
        border: '1px solid #1f2a42',
        borderRadius: '18px',
        boxShadow: '0 25px 60px rgba(0,0,0,0.8), 0 0 40px rgba(99,102,241,0.15)',
        overflow: 'hidden',
        position: 'relative',
      }}>
        {/* Close Button */}
        <button
          type="button"
          onClick={closeAuthModal}
          style={{
            position: 'absolute', right: '16px', top: '16px',
            background: 'transparent', border: 'none', color: '#64748b', cursor: 'pointer', padding: '6px',
          }}
          title="Close"
        >
          <X size={18} />
        </button>

        {/* Header */}
        <div style={{ padding: '28px 24px 20px', textAlign: 'center', borderBottom: '1px solid #162035' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: '46px', height: '46px', borderRadius: '12px',
            background: 'linear-gradient(135deg, #6366f1, #3b82f6)', marginBottom: '12px',
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <h3 style={{ margin: '0 0 6px', color: '#f8fafc', fontSize: '19px', fontWeight: 700 }}>
            Track Your Scans
          </h3>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '13px', lineHeight: 1.5 }}>
            PhishSense is free and open-source. Sign in only if you want to track personal scan history and alerts.
          </p>
        </div>

        {/* Body */}
        <div style={{ padding: '22px 24px 26px' }}>
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

          <form onSubmit={handleSignIn}>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '12.5px', color: '#94a3b8', marginBottom: '6px' }}>
                Email or Username
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={16} color="#64748b" style={{ position: 'absolute', left: '12px', top: '14px' }} />
                <input
                  type="text"
                  required
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="e.g. analyst@phishsense.io or your name"
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
                boxShadow: '0 4px 14px rgba(99, 102, 241, 0.3)',
              }}
            >
              {loading ? (
                <RefreshCw size={16} className="animate-spin" />
              ) : (
                <>
                  <span>Sign In & Start Tracking</span>
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </form>

          {/* Quick 1-Click Preset Profiles */}
          <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid #162035' }}>
            <span style={{ display: 'block', fontSize: '11px', color: '#64748b', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Instant 1-Click Profiles:
            </span>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => handleQuickPreset('analyst@phishsense.io')}
                disabled={loading}
                style={{
                  flex: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                  background: '#131b2e', border: '1px solid #222f49',
                  borderRadius: '6px', padding: '7px 10px',
                  color: '#94a3b8', fontSize: '12px', cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                <Sparkles size={13} color="#818cf8" />
                <span>Security Analyst</span>
              </button>
              <button
                type="button"
                onClick={() => handleQuickPreset('researcher@phishsense.io')}
                disabled={loading}
                style={{
                  flex: 1,
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                  background: '#131b2e', border: '1px solid #222f49',
                  borderRadius: '6px', padding: '7px 10px',
                  color: '#94a3b8', fontSize: '12px', cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                <User size={13} color="#38bdf8" />
                <span>Researcher</span>
              </button>
            </div>
          </div>

          {/* Guest Mode option */}
          <div style={{ marginTop: '16px', textAlign: 'center' }}>
            <button
              type="button"
              onClick={closeAuthModal}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#64748b',
                fontSize: '12px',
                cursor: 'pointer',
                textDecoration: 'underline',
              }}
            >
              Continue in Guest Mode (No tracking)
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
