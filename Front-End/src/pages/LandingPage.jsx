import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield, Brain, Link2, ChevronRight, Activity, Lock, Globe,
  QrCode, ScanLine, LogIn, User as UserIcon, CheckCircle2,
  AlertTriangle, ArrowRight, ShieldCheck, Zap, HelpCircle,
  Smartphone, MessageSquare, AlertCircle, Sparkles
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
        <span>PhishSense 3.5: Anonymous URL & QR threat detection for everyday users.</span>
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
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium bg-white border border-slate-200 text-slate-800 hover:bg-slate-50 transition cursor-pointer"
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
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-white border border-slate-200 text-slate-700 text-xs font-medium mb-6 shadow-sm">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
          <span>Free & Anonymous Link Verification • No Account Required</span>
        </div>

        {/* Main Headline */}
        <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-slate-950 leading-tight mb-5">
          Received a suspicious link? <br className="hidden sm:inline" />
          Check before you open it.
        </h1>

        <p className="text-base sm:text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed mb-8">
          Whether you received a WhatsApp bank alert, an SMS delivery notice, or a suspicious QR code, 
          PhishSense scans destination links in a secure sandbox and tells you in plain language whether it is safe.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-12">
          <Link
            to="/scan"
            className="btn-primary w-full sm:w-auto px-6 py-2.5 text-sm font-semibold flex items-center justify-center gap-2 text-decoration-none shadow-sm"
          >
            <ScanLine className="w-4 h-4" />
            <span>Scan a Link or QR Code Now</span>
            <ChevronRight className="w-4 h-4" />
          </Link>
          <Link
            to="/phishing-demo"
            className="btn-secondary w-full sm:w-auto px-5 py-2.5 text-sm font-medium flex items-center justify-center gap-2 text-decoration-none"
          >
            <span>Interactive Scam Lab</span>
            <ArrowRight className="w-4 h-4 text-slate-400" />
          </Link>
        </div>

        {/* Trust Signals */}
        <div className="flex flex-wrap items-center justify-center gap-6 text-xs text-slate-600 border-t border-slate-200 pt-6">
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            <span>100% Free & No Sign-In Needed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-slate-700" />
            <span>Private: Sensitive Tokens Auto-Redacted</span>
          </div>
          <div className="flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-600" />
            <span>Sub-Second Multi-Layer Analysis</span>
          </div>
        </div>
      </section>

      {/* Common Indian Scam Scenarios Section */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 mb-20">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
            <MessageSquare className="w-3.5 h-3.5 text-slate-700" />
            <span>Real-World Fraud Protection</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900">
            Have you seen messages like these recently?
          </h2>
          <p className="text-slate-500 text-xs sm:text-sm max-w-xl mx-auto mt-1">
            Over 80% of phishing attacks in India arrive via WhatsApp, SMS, or QR codes posing as essential services.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* Card 1: Bank KYC */}
          <div className="human-card p-5 bg-white border border-slate-200 hover:border-slate-300 transition space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-rose-50 flex items-center justify-center text-rose-600">
                  <AlertTriangle className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Bank KYC / PAN Suspension SMS</h3>
                  <span className="text-[11px] text-slate-400">SBI, HDFC, ICICI, PNB impersonation</span>
                </div>
              </div>
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                High Risk
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 space-y-1">
              <p className="text-[11px] text-slate-500 font-sans">Sample Message:</p>
              <p className="italic">"Dear Customer, your SBI account is blocked today. Please update your PAN immediately to unblock: <span className="text-rose-600 underline">http://sbi-kyc-pan-update.com/login</span>"</p>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              <strong>The Trap:</strong> Mimics bank netbanking portals to steal your credentials and OTPs. Official banks never send third-party .com or .xyz links.
            </p>
            <div className="pt-1">
              <Link to="/scan" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                <span>Test in Scanner</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Card 2: India Post */}
          <div className="human-card p-5 bg-white border border-slate-200 hover:border-slate-300 transition space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-amber-50 flex items-center justify-center text-amber-600">
                  <Smartphone className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">India Post / Parcel Delivery Alert</h3>
                  <span className="text-[11px] text-slate-400">India Post, Blue Dart, DTDC traps</span>
                </div>
              </div>
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                High Risk
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 space-y-1">
              <p className="text-[11px] text-slate-500 font-sans">Sample Message:</p>
              <p className="italic">"IndiaPost: Your parcel #IN8812 cannot be delivered due to incomplete address. Update address & pay ₹5 fee: <span className="text-amber-700 underline">http://indiapost-parce1-redelivery.in</span>"</p>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              <strong>The Trap:</strong> Uses the nominal ₹5 charge as an excuse to capture your debit/credit card CVV and netbanking credentials.
            </p>
            <div className="pt-1">
              <Link to="/scan" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                <span>Test in Scanner</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Card 3: Electricity Bill */}
          <div className="human-card p-5 bg-white border border-slate-200 hover:border-slate-300 transition space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-rose-50 flex items-center justify-center text-rose-600">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Electricity Bill Disconnection Threat</h3>
                  <span className="text-[11px] text-slate-400">Bijli board / Discom impersonation</span>
                </div>
              </div>
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                High Risk
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 space-y-1">
              <p className="text-[11px] text-slate-500 font-sans">Sample Message:</p>
              <p className="italic">"Urgent: Your electricity power will be disconnected tonight at 9:30 PM due to unpaid previous month bill: <span className="text-rose-600 underline">http://bijli-bill-payment-alert.xyz/pay</span>"</p>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              <strong>The Trap:</strong> Manufactures artificial panic to force quick clicks, leading to fake payment gateways or screen-sharing remote apps (AnyDesk/TeamViewer).
            </p>
            <div className="pt-1">
              <Link to="/scan" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                <span>Test in Scanner</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Card 4: QR Code & UPI Refund */}
          <div className="human-card p-5 bg-white border border-slate-200 hover:border-slate-300 transition space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center text-slate-800">
                  <QrCode className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">QR Code Cashback / Payment Reversal</h3>
                  <span className="text-[11px] text-slate-400">PhonePe, Paytm, Google Pay stickers</span>
                </div>
              </div>
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                Deceptive
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs text-slate-700 space-y-1">
              <p className="text-[11px] text-slate-500 font-sans">Sample Scheme:</p>
              <p className="italic">"Scan this QR code with your camera or UPI app to instantly receive your ₹5,000 refund/lottery prize into your account."</p>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              <strong>The Trap:</strong> You never need to scan a QR code or enter your UPI PIN to <em>receive</em> money. Scanning only authorizes money leaving your account.
            </p>
            <div className="pt-1">
              <Link to="/scan" className="text-xs font-semibold text-slate-900 hover:underline inline-flex items-center gap-1">
                <span>Decode QR Safely</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
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
                <span>Transparent Analysis Example</span>
              </div>
              <h3 className="text-base font-semibold text-slate-900">How PhishSense breaks down deceptive destinations</h3>
            </div>
            <span className="text-xs font-mono font-medium px-2.5 py-1 rounded-md bg-rose-50 text-rose-700 border border-rose-200 self-start sm:self-auto">
              Risk Score: 94 / 100 • Phishing Scam
            </span>
          </div>

          <div className="mt-5 space-y-4">
            {/* Target URL */}
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 font-mono text-xs flex flex-wrap items-center gap-1.5 text-slate-700">
              <span className="text-slate-400">http://</span>
              <span className="bg-rose-100 text-rose-800 px-1.5 py-0.5 rounded font-medium border border-rose-200">sbi-kyc-pan-update</span>
              <span className="text-slate-400">.com/</span>
              <span className="bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded">auth/netbanking</span>
            </div>

            {/* Explanation items */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">1. Brand Impersonation</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Registered domain is 'sbi-kyc-pan-update.com', not official 'onlinesbi.sbi' registered to State Bank of India.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">2. Insecure Protocol</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Served over plain HTTP without valid TLS encryption, an immediate red flag for any legitimate banking portal.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-white border border-slate-200 text-left">
                <span className="text-xs font-semibold text-slate-900 block mb-1">3. Clear Action Advice</span>
                <p className="text-xs text-slate-500 leading-relaxed">
                  "Do not enter passwords or OTPs. Report this number to 1930 or cybercrime.gov.in."
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
              desc: 'Live scan records'
            },
            {
              label: 'Phishing Traps',
              value: stats ? (stats.phishing_count ?? 0).toLocaleString() : '0',
              desc: 'Confirmed scam links'
            },
            {
              label: 'QR Codes Scanned',
              value: stats ? (stats.qr_scan_count ?? 0).toLocaleString() : '0',
              desc: 'QR destinations parsed'
            },
            {
              label: 'Verified Safe',
              value: stats ? (stats.legit_count ?? 0).toLocaleString() : '0',
              desc: 'Legitimate services'
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
            Combining machine learning, domain intelligence, and redirect isolation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {[
            {
              icon: ScanLine,
              title: 'PSL-Aware URL Dissection',
              desc: 'Inspects 16 linguistic and structural features (brand typosquatting, entropy, suspicious TLDs, token abuse) without relying solely on static blacklists.',
            },
            {
              icon: QrCode,
              title: 'QR Code Decoding Sandbox',
              desc: 'Extracts the underlying destination from photos or camera scans and evaluates it before your device can open or execute it.',
            },
            {
              icon: Globe,
              title: 'SSRF-Protected Redirection Tracing',
              desc: 'Pre-flight DNS validation prevents SSRF attacks and safely traces shortened URLs (bit.ly, tinyurl) to their real final destination.',
            },
            {
              icon: Brain,
              title: 'Random Forest Inference',
              desc: 'Trained on 10,000 real-world benign and phishing URLs, achieving 87.05% standalone lexical accuracy and 0.8568 F1-score.',
            },
            {
              icon: Link2,
              title: 'Immutable Threat Ledger',
              desc: 'Every verified phishing destination is hashed and recorded on an immutable blockchain ledger to protect other users.',
            },
            {
              icon: Lock,
              title: 'Honest Explainable Verdicts',
              desc: 'Unreachable sites are marked as INSUFFICIENT_EVIDENCE rather than falsely given a clean pass. You always receive plain-English guidance.',
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
            <h3 className="text-sm font-semibold text-slate-900">4 Practical Rules to Stay Safe from Online Scams</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">01.</span>
              <p className="text-slate-600">
                <strong>Always inspect the domain root:</strong> <code className="bg-slate-100 px-1 py-0.5 rounded text-slate-800">sbi.co.in.scam-domain.xyz</code> belongs to <code>scam-domain.xyz</code>, not State Bank of India.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">02.</span>
              <p className="text-slate-600">
                <strong>Beware artificial urgency:</strong> Messages threatening "electricity cut in 1 hour" or "account blocked today" create panic so you act before thinking.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">03.</span>
              <p className="text-slate-600">
                <strong>UPI PIN is only for sending money:</strong> You never need to enter your PIN or scan a QR code to receive payments, cashback, or refunds.
              </p>
            </div>
            <div className="flex items-start gap-2.5">
              <span className="font-semibold text-slate-900">04.</span>
              <p className="text-slate-600">
                <strong>Scan before clicking:</strong> When in doubt, copy the link or upload the QR photo to PhishSense first before opening it on your personal device.
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
            Instant machine learning analysis, brand verification, and plain-language threat verdicts. No sign-up required.
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
            For suspicious links & cyber fraud reporting in India, call National Cybercrime Helpline 1930
          </p>
        </div>
      </footer>

    </div>
  )
}
