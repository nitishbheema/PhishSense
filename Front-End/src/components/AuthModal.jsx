import React, { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { loginWithEmail } from '../utils/api'
import {
  Shield, Mail, AlertCircle, CheckCircle2, ArrowRight,
  RefreshCw, X, User, ShieldCheck
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
      setError('Please enter your name or email address.')
      return
    }

    setLoading(true)
    try {
      const res = await loginWithEmail(target)
      if (res && res.token && res.user) {
        setInfo(`Welcome, ${res.user.fullName || res.user.email}. Personalized tracking enabled.`)
        loginWithToken(res.token, res.user)
        setTimeout(() => closeAuthModal(), 500)
        return
      }

      if (res && res.error) {
        // Fallback for offline demo mode
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
          setInfo(`Demo Mode: Signed in as ${fallbackUser.fullName}. Tracking active.`)
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
    <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 z-[9999] animate-in fade-in duration-150">
      <div className="human-card w-full max-w-sm bg-white p-6 shadow-xl relative border border-slate-200">
        
        {/* Close Button */}
        <button
          type="button"
          onClick={closeAuthModal}
          className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 p-1 rounded-md transition cursor-pointer"
          title="Close dialog"
        >
          <X className="w-4 h-4" />
        </button>

        {/* Header */}
        <div className="text-center pb-4 border-b border-slate-100">
          <div className="w-10 h-10 rounded-xl bg-slate-100 flex items-center justify-center mx-auto mb-2.5 text-slate-800">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <h3 className="text-base font-semibold text-slate-900 mb-1">
            Sign In to PhishSense
          </h3>
          <p className="text-xs text-slate-500 leading-relaxed max-w-xs mx-auto">
            Save personal scan history, organize flagged traps, and track security alerts.
          </p>
        </div>

        {/* Body */}
        <div className="pt-4 space-y-3.5">
          {error && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {info && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{info}</span>
            </div>
          )}

          <form onSubmit={handleSignIn} className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1">
                Email or Username
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  required
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="e.g. analyst@phishsense.io"
                  className="clean-input w-full pl-9 pr-3 py-2 text-xs"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-2 text-xs font-medium flex items-center justify-center gap-2 cursor-pointer disabled:opacity-60"
            >
              {loading ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <span>Sign In & Continue</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Profiles */}
          <div className="pt-3 border-t border-slate-100">
            <span className="block text-[11px] font-medium text-slate-500 mb-2">
              Instant 1-Click Demo Profiles:
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleQuickPreset('analyst@phishsense.io')}
                disabled={loading}
                className="btn-secondary py-1.5 px-2 text-xs flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-slate-600" />
                <span>Analyst</span>
              </button>
              <button
                type="button"
                onClick={() => handleQuickPreset('researcher@phishsense.io')}
                disabled={loading}
                className="btn-secondary py-1.5 px-2 text-xs flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <User className="w-3.5 h-3.5 text-slate-600" />
                <span>Researcher</span>
              </button>
            </div>
          </div>

          {/* Guest Mode option */}
          <div className="text-center pt-1">
            <button
              type="button"
              onClick={closeAuthModal}
              className="text-xs text-slate-500 hover:text-slate-800 underline transition cursor-pointer"
            >
              Continue as Guest (No account needed)
            </button>
          </div>
        </div>

      </div>
    </div>
  )
}
