import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield, Brain, Link2, ChevronRight, Activity, Lock, Globe,
  QrCode, ScanLine, LogIn, User as UserIcon, CheckCircle2,
  AlertTriangle, ArrowRight, ShieldCheck, Zap, HelpCircle
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import { getDashboardStats } from '../utils/api'

export default function LandingPage() {
  const { isAuthenticated, user, openAuthModal, openProfileModal } = useAuth()
  const [stats, setStats] = useState(null)

  useEffect(() => {
    let mounted = true
    getDashboardStats().then(data => {
      if (mounted && data) {
        setStats(data)
      }
    }).catch(() => {})
    return () => { mounted = false }
  }, [])

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-900">
      
      {/* Top Banner */}
      <div className="bg-slate-100 border-b border-slate-200 px-4 py-2 text-center text-xs text-slate-600 flex items-center justify-center gap-2">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-900"></span>
        <span>PhishSense 3.5 is live: Multi-modal QR inspection and blockchain threat ledger.</span>
        <Link to="/scan" className="font-semibold text-slate-900 hover:underline ml-1">
          Open Scanner &rarr;
        </Link>
      </div>

      {/* Navigation */}
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between border-b border-slate-200">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-sm">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-base text-slate-900">PhishSense</span>
              <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                v3.5
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <Link
            to="/scan"
            className="hidden sm:flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-sm font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition"
          >
            <ScanLine className="w-4 h-4 text-slate-500" />
            <span>Threat Scanner</span>
          </Link>
          <Link
            to="/dashboard"
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-sm font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition"
          >
            <Activity className="w-4 h-4 text-slate-500" />
            <span>Dashboard</span>
          </Link>

          {isAuthenticated ? (
            <button
              onClick={openProfileModal}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium bg-white border border-slate-200 text-slate-800 hover:bg-slate-50 transition"
            >
              <UserIcon className="w-4 h-4 text-slate-600" />
              <span>{user?.fullName || user?.email?.split('@')[0] || 'My Account'}</span>
            </button>
          ) : (
            <button
              onClick={openAuthModal}
              className="btn-primary flex items-center gap-2 px-4 py-1.5 text-sm font-medium cursor-pointer"
            >
              <LogIn className="w-4 h-4" />
              <span>Sign In</span>
            </button>
          )}
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-16 pb-16 px-4 sm:px-6 lg:px-8 max-w-4xl mx-auto text-center">
        
        {/* Category Pill */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-slate-200 text-slate-700 text-xs font-medium mb-6 shadow-sm">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Real-time Phishing, QR Code & Domain Impersonation Defense</span>
        </div>

        {/* Main Headline */}
        <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-slate-950 leading-tight mb-5">
          Detect deceptive links before <br className="hidden sm:inline" />
          they compromise your personal data.
        </h1>

        <p className="text-base sm:text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed mb-8">
          PhishSense analyzes cloaked redirects, typosquatting domains, and credential traps in under a second. 
          Clear explanations without confusing technical jargon.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-14">
          <Link
            to="/scan"
            className="btn-primary w-full sm:w-auto px-6 py-2.5 text-sm font-semibold flex items-center justify-center gap-2 text-decoration-none shadow-sm"
          >
            <ScanLine className="w-4 h-4" />
            <span>Launch Free Threat Scanner</span>
            <ChevronRight className="w-4 h-4" />
          </Link>
          <Link
            to="/phishing-demo"
            className="btn-secondary w-full sm:w-auto px-5 py-2.5 text-sm font-medium flex items-center justify-center gap-2 text-decoration-none"
          >
            <span>Interactive Phishing Lab</span>
            <ArrowRight className="w-4 h-4 text-slate-400" />
          </Link>
        </div>

        {/* Trust Signals */}
        <div className="flex flex-wrap items-center justify-center gap-6 text-xs text-slate-500 border-t border-slate-200 pt-6">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-slate-700" />
            <span>No Account Required to Scan</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-slate-700" />
            <span>Privacy Guard: URLs Never Stored Publicly</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-slate-700" />
            <span>Sub-Second Response Time</span>
          </div>
        </div>
      </section>

      {/* Visual Example Card */}
      <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
        <div className="human-card p-6 bg-white border border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100">
            <div>
              <div className="flex items-center gap-1.5 text-rose-600 text-xs font-semibold mb-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Example Threat Analysis</span>
              </div>
              <h3 className="text-base font-semibold text-slate-900">How PhishSense breaks down deceptive links</h3>
            </div>
            <span className="text-xs font-mono font-medium px-2.5 py-1 rounded-md bg-rose-50 text-rose-700 border border-rose-200 self-start sm:self-auto">
              Risk Score: 96 / 100 • Critical
            </span>
          </div>

          <div className="mt-5 space-y-4">
            {/* Target URL */}
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs flex flex-wrap items-center gap-1.5 text-slate-700">
              <span className="text-slate-400">https://</span>
              <span className="bg-rose-100 text-rose-800 px-1.5 py-0.5 rounded font-medium border border-rose-200">paypa1-account-security</span>
              <span className="text-slate-400">.xyz/</span>
              <span className="bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded">verify?redirect=stealth</span>
            </div>

            {/* Explanation items */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">1. Typo-Squatting</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Replaced letter 'l' with numeral '1' to mimic authentic PayPal domain.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">2. High-Risk TLD</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Disposable top-level domain registered 48 hours ago without WHOIS records.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">3. Hidden Redirection</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Script silently relays entered passwords to an unverified secondary receiver.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Real Database Statistics */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            {
              label: 'Links Scanned',
              value: stats ? (stats.total_scans ?? stats.total_threats ?? stats.url_scan_count ?? 0).toLocaleString() : '0',
              desc: 'Live database records'
            },
            {
              label: 'Phishing Traps',
              value: stats ? (stats.phishing_count ?? 0).toLocaleString() : '0',
              desc: 'Confirmed malicious traps'
            },
            {
              label: 'QR Codes Scanned',
              value: stats ? (stats.qr_scan_count ?? 0).toLocaleString() : '0',
              desc: 'QR payloads inspected'
            },
            {
              label: 'Verified Safe',
              value: stats ? (stats.legit_count ?? 0).toLocaleString() : '0',
              desc: 'Clean domains confirmed'
            },
          ].map(({ label, value, desc }) => (
            <div key={label} className="human-card p-5 text-left bg-white border-slate-200">
              <div className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 mb-1">
                {value}
              </div>
              <div className="text-xs font-medium text-slate-800">{label}</div>
              <div className="text-[11px] text-slate-400 mt-0.5">{desc}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Capabilities */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
        <div className="text-center mb-10">
          <h2 className="text-2xl font-bold text-slate-900 mb-2">
            Multi-Layer Protection Capabilities
          </h2>
          <p className="text-slate-500 text-sm max-w-md mx-auto">
            Comprehensive verification designed for everyday browsing safety.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {[
            {
              icon: ScanLine,
              title: 'URL Dissection',
              desc: 'Inspects 16 linguistic and structural indicators (entropy, hyphens, token abuse) without relying only on outdated blacklists.',
            },
            {
              icon: QrCode,
              title: 'QR Code Decoding',
              desc: 'Safely inspect QR destinations from photos or camera before your phone or browser visits the link.',
            },
            {
              icon: Globe,
              title: 'Webpage Emulation',
              desc: 'Scans for hidden iframes, password input traps, external CDN script hijacking, and fake brand logos.',
            },
            {
              icon: Brain,
              title: 'Behavioral ML',
              desc: 'Machine learning models analyze interaction patterns to detect anomaly signatures during credential input.',
            },
            {
              icon: Link2,
              title: 'Tamper-Proof Ledger',
              desc: 'Every confirmed scam signature is hashed on an immutable blockchain ledger to permanently alert future users.',
            },
            {
              icon: Lock,
              title: 'Clear Action Advice',
              desc: 'Verdicts are written in plain language with specific guidance on whether the site is safe to use.',
            },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="human-card p-5 flex flex-col justify-between bg-white border-slate-200">
              <div>
                <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-slate-700 mb-3">
                  <Icon className="w-4 h-4" />
                </div>
                <h3 className="text-sm font-semibold text-slate-900 mb-1.5">
                  {title}
                </h3>
                <p className="text-xs text-slate-500 leading-relaxed">
                  {desc}
                </p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Safety Guidelines */}
      <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
        <div className="human-card p-6 bg-white border-slate-200">
          <div className="flex items-center gap-2 mb-4">
            <HelpCircle className="w-4 h-4 text-slate-700" />
            <h3 className="text-sm font-semibold text-slate-900">Basic Safety Rules Before Clicking Any Link</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">01.</span>
              <p className="text-slate-600">
                <strong>Always verify the domain root:</strong> <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-800">paypal.com.scam-host.net</code> is hosted on <code>scam-host.net</code>, not PayPal.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">02.</span>
              <p className="text-slate-600">
                <strong>Beware artificial urgency:</strong> Messages threatening immediate account suspension are almost always phishing traps.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">03.</span>
              <p className="text-slate-600">
                <strong>Inspect physical QR stickers:</strong> Verify that parking meter or restaurant payment QR codes haven't been pasted over with fake stickers.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">04.</span>
              <p className="text-slate-600">
                <strong>Scan with PhishSense:</strong> When uncertain, paste the address here first before opening it on your personal device.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom CTA */}
      <section className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-16 text-center">
        <div className="human-card p-8 bg-slate-900 text-white border-none shadow-md">
          <h2 className="text-xl sm:text-2xl font-bold text-white mb-2">
            Ready to inspect a suspicious link or QR code?
          </h2>
          <p className="text-slate-300 text-xs sm:text-sm max-w-md mx-auto mb-6">
            Instant machine learning analysis, brand verification, and plain-language threat verdicts.
          </p>
          <Link
            to="/scan"
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-white text-slate-950 font-semibold text-sm hover:bg-slate-100 transition shadow-sm text-decoration-none"
          >
            <ScanLine className="w-4 h-4" />
            <span>Open Threat Scanner</span>
            <ChevronRight className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-200 py-6 px-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-slate-700" />
            <span className="font-medium text-slate-700">PhishSense v3.5</span>
            <span>— Intelligent Phishing Detection Platform</span>
          </div>
          <p className="text-slate-400">
            Final Year Research Project • Clean White UI
          </p>
        </div>
      </footer>

    </div>
  )
}
