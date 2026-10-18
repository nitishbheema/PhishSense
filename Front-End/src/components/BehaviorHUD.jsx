import { useState } from 'react'
import { Activity, ChevronDown, ChevronUp, Shield, AlertTriangle } from 'lucide-react'

/**
 * BehaviorHUD
 * A collapsible live panel showing real-time behavioral metrics.
 * Used in demo pages so the examiner can see tracking in action.
 */
export default function BehaviorHUD({ snapshot, position = 'bottom-right' }) {
  const [collapsed, setCollapsed] = useState(false)

  if (!snapshot) return null

  const s = snapshot
  const score = s.anomalyScore || 0
  const scoreColor = score >= 70 ? '#dc2626' : score >= 40 ? '#f59e0b' : '#10b981'
  const scoreLabel = score >= 70 ? 'High Risk' : score >= 40 ? 'Suspicious' : 'Normal'

  const posStyle = {
    'bottom-right': { bottom: '20px', right: '20px' },
    'bottom-left': { bottom: '20px', left: '20px' },
    'top-right': { top: '80px', right: '20px' },
  }[position] || { bottom: '20px', right: '20px' }

  const avgTypingDelay = s.typingDelays.length
    ? Math.round(s.typingDelays.reduce((a, b) => a + b, 0) / s.typingDelays.length)
    : 0

  const avgMouseSpeed = s.mouseSpeed.length
    ? (s.mouseSpeed.reduce((a, b) => a + b, 0) / s.mouseSpeed.length).toFixed(2)
    : 0

  return (
    <div style={{
      position: 'fixed', ...posStyle, zIndex: 9000,
      background: '#0f0f1a', border: '1px solid #1a1a2e',
      borderRadius: '12px', width: '240px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
      fontFamily: 'DM Sans, sans-serif', overflow: 'hidden',
    }}>

      {/* Header */}
      <div
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 12px', cursor: 'pointer',
          borderBottom: collapsed ? 'none' : '1px solid #1a1a2e',
          background: '#111120',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>
          <Activity size={13} color="#818cf8" />
          <span style={{ fontSize: '12px', fontWeight: 600, color: '#818cf8' }}>
            PhishGuard Tracker
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{
            fontSize: '11px', fontWeight: 700, color: scoreColor,
            background: scoreColor + '18', borderRadius: '4px', padding: '2px 6px',
          }}>
            {score}
          </span>
          {collapsed ? <ChevronDown size={12} color="#555" /> : <ChevronUp size={12} color="#555" />}
        </div>
      </div>

      {!collapsed && (
        <div style={{ padding: '10px 12px' }}>

          {/* Anomaly Score Bar */}
          <div style={{ marginBottom: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '5px' }}>
              <span style={{ fontSize: '11px', color: '#555' }}>Anomaly Score</span>
              <span style={{ fontSize: '11px', fontWeight: 700, color: scoreColor }}>{scoreLabel}</span>
            </div>
            <div style={{ height: '5px', background: '#1a1a2e', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{
                width: `${score}%`, height: '100%',
                background: scoreColor, borderRadius: '3px',
                transition: 'width 0.4s ease',
              }} />
            </div>
          </div>

          {/* Metrics grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', marginBottom: '10px' }}>
            {[
              { label: 'Mouse pts', value: s.mousePath.length },
              { label: 'Clicks', value: s.clicks.length },
              { label: 'Keystrokes', value: s.keystrokes.length },
              { label: 'Avg delay', value: avgTypingDelay ? `${avgTypingDelay}ms` : '—' },
              { label: 'Mouse spd', value: avgMouseSpeed ? `${avgMouseSpeed}` : '—' },
              { label: 'Pastes', value: s.pasteCount, alert: s.pasteCount > 0 },
              { label: 'Rapid clicks', value: s.rapidClicks, alert: s.rapidClicks > 3 },
              { label: 'Scroll depth', value: `${s.scrollDepth.toFixed(0)}%` },
            ].map(({ label, value, alert }) => (
              <div key={label} style={{
                background: alert ? '#1a0a0a' : '#0a0a12',
                border: `1px solid ${alert ? '#3a1010' : '#111120'}`,
                borderRadius: '6px', padding: '6px 8px',
              }}>
                <div style={{ fontSize: '10px', color: '#444' }}>{label}</div>
                <div style={{ fontSize: '13px', fontWeight: 600, color: alert ? '#dc2626' : '#e8e8f0', marginTop: '1px' }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Flags */}
          {s.flags && s.flags.length > 0 && (
            <div>
              <div style={{ fontSize: '10px', color: '#555', marginBottom: '5px', fontWeight: 600 }}>
                FLAGS DETECTED
              </div>
              {s.flags.slice(0, 3).map((flag, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'flex-start', gap: '5px',
                  marginBottom: '3px', fontSize: '10px', color: '#f87171', lineHeight: 1.4,
                }}>
                  <AlertTriangle size={9} style={{ marginTop: '2px', flexShrink: 0 }} />
                  {flag}
                </div>
              ))}
            </div>
          )}

          {s.flags && s.flags.length === 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: '#10b981' }}>
              <Shield size={11} />
              No anomalies detected yet
            </div>
          )}

          <div style={{ marginTop: '8px', fontSize: '10px', color: '#333', textAlign: 'right' }}>
            Session: {s.sessionId?.slice(0, 8)}...
          </div>
        </div>
      )}
    </div>
  )
}
