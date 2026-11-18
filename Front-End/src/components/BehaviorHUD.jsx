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
  const scoreColor = score >= 70 ? '#e11d48' : score >= 40 ? '#d97706' : '#059669'
  const scoreLabel = score >= 70 ? 'High Risk' : score >= 40 ? 'Suspicious' : 'Normal'

  const posStyle = {
    'bottom-right': { bottom: '20px', right: '20px' },
    'bottom-left': { bottom: '20px', left: '20px' },
    'top-right': { top: '80px', right: '20px' },
  }[position] || { bottom: '20px', right: '20px' }

  const avgTypingDelay = s.typingDelays?.length
    ? Math.round(s.typingDelays.reduce((a, b) => a + b, 0) / s.typingDelays.length)
    : 0

  const avgMouseSpeed = s.mouseSpeed?.length
    ? (s.mouseSpeed.reduce((a, b) => a + b, 0) / s.mouseSpeed.length).toFixed(2)
    : 0

  return (
    <div
      style={{
        position: 'fixed', ...posStyle, zIndex: 9000,
      }}
      className="human-card w-64 bg-white border border-slate-200 shadow-lg text-slate-900 overflow-hidden"
    >
      {/* Header */}
      <div
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-between p-2.5 cursor-pointer bg-slate-50 border-b border-slate-200 hover:bg-slate-100 transition"
      >
        <div className="flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-slate-700" />
          <span className="text-xs font-semibold text-slate-900">
            Biometrics Telemetry
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="text-[11px] font-semibold font-mono px-1.5 py-0.2 rounded"
            style={{
              color: scoreColor,
              backgroundColor: `${scoreColor}15`,
            }}
          >
            {score}%
          </span>
          {collapsed ? <ChevronDown className="w-3.5 h-3.5 text-slate-400" /> : <ChevronUp className="w-3.5 h-3.5 text-slate-400" />}
        </div>
      </div>

      {!collapsed && (
        <div className="p-3 space-y-2.5 text-xs">
          {/* Anomaly Score Bar */}
          <div>
            <div className="flex justify-between items-center mb-1 text-[11px]">
              <span className="text-slate-500">Anomaly Index</span>
              <span className="font-semibold font-mono" style={{ color: scoreColor }}>{scoreLabel}</span>
            </div>
            <div className="h-1.5 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{ width: `${score}%`, backgroundColor: scoreColor }}
              />
            </div>
          </div>

          {/* Metrics grid */}
          <div className="grid grid-cols-2 gap-1.5">
            {[
              { label: 'Mouse Points', value: s.mousePath?.length || 0 },
              { label: 'Total Clicks', value: s.clicks?.length || 0 },
              { label: 'Keystrokes', value: s.keystrokes?.length || 0 },
              { label: 'Typing Delay', value: avgTypingDelay ? `${avgTypingDelay}ms` : '—' },
              { label: 'Mouse Speed', value: avgMouseSpeed ? `${avgMouseSpeed}` : '—' },
              { label: 'Pastes', value: s.pasteCount || 0, alert: (s.pasteCount || 0) > 0 },
              { label: 'Rapid Clicks', value: s.rapidClicks || 0, alert: (s.rapidClicks || 0) > 3 },
              { label: 'Scroll Depth', value: `${(s.scrollDepth || 0).toFixed(0)}%` },
            ].map(({ label, value, alert }) => (
              <div
                key={label}
                className={`p-1.5 rounded-md border ${
                  alert
                    ? 'bg-rose-50 border-rose-200 text-rose-700'
                    : 'bg-slate-50 border-slate-200 text-slate-800'
                }`}
              >
                <div className="text-[10px] text-slate-400">{label}</div>
                <div className="text-xs font-mono font-semibold mt-0.5">{value}</div>
              </div>
            ))}
          </div>

          {/* Flags */}
          {s.flags && s.flags.length > 0 ? (
            <div className="space-y-1 pt-0.5">
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">
                Detected Flags:
              </span>
              {s.flags.slice(0, 3).map((flag, i) => (
                <div key={i} className="flex items-start gap-1 text-[11px] text-rose-700">
                  <AlertTriangle className="w-3 h-3 text-rose-600 shrink-0 mt-0.5" />
                  <span className="leading-tight">{flag}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-[11px] text-emerald-700 pt-0.5">
              <Shield className="w-3 h-3" />
              <span>Normal human interaction cadence</span>
            </div>
          )}

          <div className="text-[10px] font-mono text-slate-400 text-right pt-1 border-t border-slate-100">
            Session: {s.sessionId?.slice(0, 8)}...
          </div>
        </div>
      )}
    </div>
  )
}
