import { Link } from 'react-router-dom'
import { Shield, Brain, Link2, ChevronRight, Activity, Lock, Globe, QrCode, ScanLine, LogIn, User as UserIcon } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function LandingPage() {
  const { isAuthenticated, user, openAuthModal, openProfileModal } = useAuth()

  return (
    <div style={{ minHeight: '100vh', background: '#0a0a0f' }}>

      {/* Nav */}
      <nav style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '1.2rem 3rem', borderBottom: '1px solid #1a1a2e',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield size={22} color="#6366f1" />
          <span style={{ fontWeight: 700, fontSize: '16px', letterSpacing: '-0.4px' }}>PhishSense</span>
          <span style={{
            fontSize: '10px', background: '#1e1e3a', color: '#818cf8',
            border: '1px solid #2a2a50', borderRadius: '4px',
            padding: '2px 7px', fontWeight: 500,
          }}>v3.5</span>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <Link to="/scan" style={{
            padding: '8px 18px', borderRadius: '8px', fontSize: '13px',
            border: '1px solid #2a2a3e', color: '#aaa', textDecoration: 'none',
          }}>Threat Scanner</Link>
          <Link to="/dashboard" style={{
            padding: '8px 18px', borderRadius: '8px', fontSize: '13px',
            background: '#1e1e3a', border: '1px solid #2a2a50', color: '#818cf8', textDecoration: 'none',
            fontWeight: 500,
          }}>Dashboard →</Link>

          {isAuthenticated ? (
            <button
              onClick={openProfileModal}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                padding: '7px 14px', borderRadius: '8px', fontSize: '13px',
                background: '#141829', border: '1px solid #28334e', color: '#e2e8f0',
                cursor: 'pointer', fontWeight: 500,
              }}
            >
              <UserIcon size={14} color="#818cf8" />
              {user?.fullName || user?.email?.split('@')[0] || 'My Account'}
            </button>
          ) : (
            <button
              onClick={openAuthModal}
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                padding: '7px 16px', borderRadius: '8px', fontSize: '13px',
                background: 'linear-gradient(135deg, #6366f1, #4f46e5)', border: 'none',
                color: '#fff', cursor: 'pointer', fontWeight: 600,
                boxShadow: '0 2px 10px rgba(99,102,241,0.3)',
              }}
            >
              <LogIn size={14} />
              Sign In
            </button>
          )}
        </div>
      </nav>

      {/* Hero */}
      <section style={{
        textAlign: 'center', padding: '6rem 2rem 4rem',
        maxWidth: '800px', margin: '0 auto',
      }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '8px',
          background: '#1a1a2e', border: '1px solid #2a2a40',
          borderRadius: '999px', padding: '6px 14px', marginBottom: '2rem',
          fontSize: '12px', color: '#818cf8',
        }}>
          <Activity size={12} />
          URL · QR Code · Website Analysis · Blockchain Threat Intelligence
        </div>

        <h1 style={{
          fontSize: 'clamp(2.2rem, 5vw, 3.5rem)',
          fontWeight: 700, lineHeight: 1.15,
          letterSpacing: '-1.5px', marginBottom: '1.2rem',
          background: 'linear-gradient(135deg, #e8e8f0 0%, #818cf8 60%, #6366f1 100%)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        }}>
          Unified Digital Threat<br />Detection Platform
        </h1>

        <p style={{
          fontSize: '17px', color: '#666', lineHeight: 1.7,
          maxWidth: '560px', margin: '0 auto 2.5rem',
        }}>
          PhishSense detects phishing across URLs, QR codes, and websites.
          Behavioral fingerprinting, AI analysis, and blockchain threat intelligence
          — in one platform.
        </p>

        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/scan" style={{
            padding: '12px 28px', borderRadius: '10px',
            background: '#6366f1', color: '#fff', textDecoration: 'none',
            fontWeight: 600, fontSize: '15px', display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            Scan a Threat <ChevronRight size={16} />
          </Link>
          <Link to="/phishing-demo" style={{
            padding: '12px 28px', borderRadius: '10px',
            border: '1px solid #2a2a3e', color: '#aaa', textDecoration: 'none',
            fontSize: '15px',
          }}>
            View Phishing Demo
          </Link>
        </div>
      </section>

      {/* Stats */}
      <section style={{
        display: 'flex', justifyContent: 'center', gap: '2rem',
        padding: '2rem', flexWrap: 'wrap',
      }}>
        {[
          { label: 'Threats Detected',   value: '12,847' },
          { label: 'Accuracy Rate',       value: '97.3%'  },
          { label: 'Blocked Today',       value: '284'    },
          { label: 'QR Threats Caught',   value: '189'    },
        ].map(({ label, value }) => (
          <div key={label} style={{
            background: '#0f0f1a', border: '1px solid #1a1a2e',
            borderRadius: '12px', padding: '1.5rem 2.5rem', textAlign: 'center',
          }}>
            <div style={{ fontSize: '28px', fontWeight: 700, color: '#818cf8', letterSpacing: '-1px' }}>{value}</div>
            <div style={{ fontSize: '13px', color: '#555', marginTop: '4px' }}>{label}</div>
          </div>
        ))}
      </section>

      {/* Features */}
      <section style={{
        maxWidth: '1000px', margin: '3rem auto',
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '16px', padding: '0 2rem',
      }}>
        {[
          {
            icon: ScanLine, title: 'URL Threat Analysis',
            desc: 'Extracts 16 URL features and runs them through a trained Random Forest model to detect phishing URLs.',
            color: '#818cf8',
          },
          {
            icon: QrCode, title: 'QR Code Scanner',
            desc: 'Decode QR codes via camera or upload. Destination URL is analyzed before you visit — preventing blind redirects to malicious sites.',
            color: '#f472b6',
          },
          {
            icon: Globe, title: 'Website Signal Analysis',
            desc: 'Deep analysis of webpage DOM, forms, scripts, iframes, and redirects to detect impersonation and phishing structure.',
            color: '#fb923c',
          },
          {
            icon: Brain, title: 'AI Behavioral Analysis',
            desc: 'Random Forest and XGBoost models analyze mouse movements, typing rhythm, and click patterns to detect interaction anomalies.',
            color: '#34d399',
          },
          {
            icon: Link2, title: 'Blockchain Threat Ledger',
            desc: 'Detected threat fingerprints are stored in a tamper-proof PoW blockchain. Previous threats are reused to improve future detections.',
            color: '#60a5fa',
          },
          {
            icon: Lock, title: 'AI/Deception Risk Scoring',
            desc: 'Estimates synthetic/deceptive content likelihood based on measurable signals — brand impersonation, JS patterns, and structural anomalies.',
            color: '#c084fc',
          },
        ].map(({ icon: Icon, title, desc, color }) => (
          <div key={title} style={{
            background: '#0f0f1a', border: '1px solid #1a1a2e',
            borderRadius: '12px', padding: '1.5rem',
          }}>
            <div style={{
              width: '40px', height: '40px', borderRadius: '10px',
              background: color + '15', display: 'flex', alignItems: 'center',
              justifyContent: 'center', marginBottom: '1rem',
            }}>
              <Icon size={20} color={color} />
            </div>
            <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '8px', color: '#e8e8f0' }}>{title}</h3>
            <p style={{ fontSize: '13px', color: '#555', lineHeight: 1.6, margin: 0 }}>{desc}</p>
          </div>
        ))}
      </section>

      {/* Footer */}
      <footer style={{
        textAlign: 'center', padding: '2rem',
        borderTop: '1px solid #1a1a2e', color: '#444', fontSize: '13px', marginTop: '2rem',
      }}>
        PhishSense v3.0 — Unified AI & Behavioral Phishing Detection · Final Year Research Project
      </footer>
    </div>
  )
}
