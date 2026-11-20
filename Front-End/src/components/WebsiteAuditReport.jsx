import React, { useState } from 'react'
import {
  Shield, ShieldAlert, ShieldCheck, AlertTriangle, AlertCircle,
  CheckCircle2, XCircle, Globe, Server, Cpu, Database, History,
  Clock, FileCode, Lock, Key, ChevronDown, ChevronUp, ExternalLink,
  RefreshCw, Copy, Check, Terminal, Layers, Activity, Eye, Zap, Info, Bug
} from 'lucide-react'

const CATEGORY_ICONS = {
  PHISHING_RISK: ShieldAlert,
  MALWARE_AND_THREAT_INTEL: Database,
  COMPROMISE_INDICATORS: AlertTriangle,
  TECHNOLOGY_LIFECYCLE: Cpu,
  KNOWN_VULNERABILITIES: Bug,
  TLS_AND_CERTIFICATES: Lock,
  HTTP_SECURITY_HEADERS: FileCode,
  DOMAIN_REGISTRATION_AND_DNS: Globe,
  DEPLOYMENT_AND_CHANGE_HISTORY: History,
  WEBSITE_HEALTH_AND_AVAILABILITY: Activity,
}

const STATUS_CONFIG = {
  CRITICAL: {
    label: 'Critical Risk',
    color: '#e11d48',
    bg: '#fff1f2',
    border: '#fecdd3',
    badgeBg: '#ffe4e6',
    badgeText: '#be123c',
    icon: XCircle,
  },
  HIGH: {
    label: 'High Severity',
    color: '#e11d48',
    bg: '#fff1f2',
    border: '#fecdd3',
    badgeBg: '#ffe4e6',
    badgeText: '#be123c',
    icon: AlertTriangle,
  },
  MEDIUM: {
    label: 'Moderate Warning',
    color: '#d97706',
    bg: '#fffbeb',
    border: '#fde68a',
    badgeBg: '#fef3c7',
    badgeText: '#b45309',
    icon: AlertCircle,
  },
  LOW: {
    label: 'Low Advisory',
    color: '#64748b',
    bg: '#f8fafc',
    border: '#e2e8f0',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    icon: Info,
  },
  INFORMATIONAL: {
    label: 'Informational',
    color: '#0284c7',
    bg: '#f0f9ff',
    border: '#bae6fd',
    badgeBg: '#e0f2fe',
    badgeText: '#0369a1',
    icon: Info,
  },
  NO_ISSUE_DETECTED: {
    label: 'No Issue Detected',
    color: '#059669',
    bg: '#f0fdf4',
    border: '#bbf7d0',
    badgeBg: '#dcfce7',
    badgeText: '#047857',
    icon: CheckCircle2,
  },
  INSUFFICIENT_EVIDENCE: {
    label: 'Insufficient Evidence',
    color: '#64748b',
    bg: '#f8fafc',
    border: '#cbd5e1',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    icon: AlertCircle,
  },
  UNREACHABLE: {
    label: 'Host Unreachable',
    color: '#64748b',
    bg: '#f8fafc',
    border: '#cbd5e1',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    icon: AlertCircle,
  },
  SCAN_FAILED: {
    label: 'Scan Incomplete',
    color: '#64748b',
    bg: '#f8fafc',
    border: '#cbd5e1',
    badgeBg: '#f1f5f9',
    badgeText: '#475569',
    icon: AlertCircle,
  },
}

function getStatusCfg(status) {
  const key = (status || '').toUpperCase()
  return STATUS_CONFIG[key] || STATUS_CONFIG.LOW
}

export default function WebsiteAuditReport({ auditData, onRescan }) {
  const [expandedCats, setExpandedCats] = useState({})
  const [filterMode, setFilterMode] = useState('ALL')
  const [copiedText, setCopiedText] = useState(false)

  if (!auditData) return null

  const exec = auditData.executive_summary || {}
  const counts = exec.issue_counts || {}
  const categories = auditData.categories || []
  const postureCfg = getStatusCfg(exec.posture_badge || 'LOW')

  const toggleCat = (id) => {
    setExpandedCats(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const expandAll = () => {
    const all = {}
    categories.forEach(c => { all[c.category_id] = true })
    setExpandedCats(all)
  }

  const collapseAll = () => {
    setExpandedCats({})
  }

  const filteredCategories = categories.filter(c => {
    if (filterMode === 'CRITICAL_HIGH') {
      return c.status === 'CRITICAL' || c.status === 'HIGH'
    }
    if (filterMode === 'WARNINGS') {
      return c.status === 'CRITICAL' || c.status === 'HIGH' || c.status === 'MEDIUM'
    }
    if (filterMode === 'CLEAN') {
      return c.status === 'NO_ISSUE_DETECTED'
    }
    return true
  })

  return (
    <div className="space-y-6 animate-in fade-in duration-200 text-slate-900">
      
      {/* ── 1. EXECUTIVE SECURITY POSTURE OVERVIEW ── */}
      <div
        className="human-card p-6 bg-white border border-slate-200 shadow-sm relative overflow-hidden"
        style={{ borderTop: `4px solid ${postureCfg.color}` }}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-100">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Website Security & Health Report
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                {auditData.assessment_mode}
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-950 flex items-center gap-2">
              <span>{auditData.target_domain}</span>
            </h2>
            <div className="text-xs text-slate-500 font-mono mt-0.5 truncate max-w-xl">
              Target: {auditData.target_url}
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2 shrink-0">
            <div
              className="px-3.5 py-1.5 rounded-xl border flex items-center gap-2"
              style={{ backgroundColor: postureCfg.bg, borderColor: postureCfg.border, color: postureCfg.badgeText }}
            >
              <postureCfg.icon className="w-4 h-4" />
              <span className="text-xs font-bold">{exec.posture_label || 'Audit Complete'}</span>
            </div>
          </div>
        </div>

        {/* Executive Summary Narrative */}
        <p className="text-xs sm:text-sm text-slate-700 leading-relaxed my-4">
          {exec.summary}
        </p>

        {/* Categorical Issue Counts Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 pt-2 border-t border-slate-100">
          <div className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-center">
            <span className="text-xl font-bold text-rose-700 font-mono">{counts.critical || 0}</span>
            <span className="block text-[11px] font-medium text-rose-800">Critical</span>
          </div>
          <div className="p-2.5 rounded-lg bg-rose-50/70 border border-rose-200 text-center">
            <span className="text-xl font-bold text-rose-600 font-mono">{counts.high || 0}</span>
            <span className="block text-[11px] font-medium text-rose-700">High Risk</span>
          </div>
          <div className="p-2.5 rounded-lg bg-amber-50 border border-amber-200 text-center">
            <span className="text-xl font-bold text-amber-700 font-mono">{counts.medium || 0}</span>
            <span className="block text-[11px] font-medium text-amber-800">Medium</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-center">
            <span className="text-xl font-bold text-slate-700 font-mono">{counts.low || 0}</span>
            <span className="block text-[11px] font-medium text-slate-600">Low Risk</span>
          </div>
          <div className="p-2.5 rounded-lg bg-sky-50 border border-sky-200 text-center">
            <span className="text-xl font-bold text-sky-700 font-mono">{counts.informational || 0}</span>
            <span className="block text-[11px] font-medium text-sky-800">Info / Notes</span>
          </div>
          <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-center">
            <span className="text-xl font-bold text-emerald-700 font-mono">{counts.clean || 0}</span>
            <span className="block text-[11px] font-medium text-emerald-800">Clean Passes</span>
          </div>
        </div>

        {/* Audit Meta Footer */}
        <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 font-mono pt-4 mt-2 border-t border-slate-100">
          <span>Audit Timestamp: {auditData.audit_timestamp_utc ? auditData.audit_timestamp_utc.replace('T', ' ').slice(0, 19) + ' UTC' : 'Live'}</span>
          <span>Latency: {auditData.execution_duration_ms} ms • 10 Independent Categories</span>
        </div>
      </div>

      {/* ── 2. CATEGORY FILTER & VIEW TOGGLES ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2">
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-slate-500 font-medium mr-1">Filter Findings:</span>
          {[
            { key: 'ALL', label: `All Categories (${categories.length})` },
            { key: 'WARNINGS', label: `Issues (${(counts.critical || 0) + (counts.high || 0) + (counts.medium || 0)})` },
            { key: 'CLEAN', label: `Clean (${counts.clean || 0})` },
          ].map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setFilterMode(key)}
              className={`px-3 py-1 rounded-lg border text-xs font-medium cursor-pointer transition ${
                filterMode === key
                  ? 'bg-slate-900 text-white border-slate-900 font-semibold'
                  : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={expandAll}
            className="text-slate-600 hover:text-slate-900 underline cursor-pointer"
          >
            Expand All Details
          </button>
          <span>•</span>
          <button
            onClick={collapseAll}
            className="text-slate-600 hover:text-slate-900 underline cursor-pointer"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* ── 3. DETAILED 10-CATEGORY AUDIT ACCORDIONS ── */}
      <div className="space-y-3.5">
        {filteredCategories.map((cat, idx) => {
          const cfg = getStatusCfg(cat.status)
          const Icon = CATEGORY_ICONS[cat.category_id] || Shield
          const isExpanded = !!expandedCats[cat.category_id]
          const ev = cat.evidence || {}

          return (
            <div
              key={cat.category_id}
              className="human-card bg-white border border-slate-200 rounded-xl overflow-hidden transition hover:border-slate-300"
            >
              {/* Category Header Bar */}
              <div
                onClick={() => toggleCat(cat.category_id)}
                className="p-4 sm:p-5 flex items-start sm:items-center justify-between gap-3 cursor-pointer select-none bg-white hover:bg-slate-50/60 transition"
              >
                <div className="flex items-start sm:items-center gap-3">
                  <div
                    className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 mt-0.5 sm:mt-0"
                    style={{ backgroundColor: cfg.bg, color: cfg.badgeText }}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-slate-400 font-mono">0{idx + 1}.</span>
                      <h3 className="text-sm font-bold text-slate-900 m-0">
                        {cat.category_name}
                      </h3>
                      <span
                        className="text-[10px] font-semibold px-2 py-0.5 rounded-full border font-mono"
                        style={{ backgroundColor: cfg.badgeBg, color: cfg.badgeText, borderColor: cfg.border }}
                      >
                        {cfg.label}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                      {cat.finding}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
                    {isExpanded ? 'Hide Evidence' : 'View Evidence'}
                  </span>
                  <div className="w-7 h-7 rounded-lg bg-slate-100 flex items-center justify-center text-slate-500">
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </div>
                </div>
              </div>

              {/* Expandable Technical Evidence & Guidance Panel */}
              {isExpanded && (
                <div className="px-5 pb-5 pt-2 border-t border-slate-100 space-y-4 bg-slate-50/50 text-xs animate-in fade-in duration-150">
                  
                  {/* Why It Matters */}
                  <div className="p-3 rounded-lg bg-white border border-slate-200">
                    <span className="font-semibold text-slate-900 block mb-0.5">Why This Matters:</span>
                    <p className="text-slate-600 leading-relaxed">{cat.why_it_matters}</p>
                  </div>

                  {/* Recommended Action */}
                  <div className="p-3 rounded-lg bg-emerald-50/60 border border-emerald-200 text-emerald-900">
                    <span className="font-semibold text-emerald-950 block mb-0.5">Recommended Remediation:</span>
                    <p className="text-emerald-800 leading-relaxed">{cat.recommended_action}</p>
                  </div>

                  {/* Specific Evidence Views depending on Category */}

                  {/* Category 4: Technologies & Outdated Software */}
                  {cat.category_id === 'TECHNOLOGY_LIFECYCLE' && ev.technologies && (
                    <div className="space-y-2">
                      <span className="font-semibold text-slate-800 block">Identified Technology Components:</span>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {ev.technologies.map((t, ti) => (
                          <div key={ti} className="p-3 rounded-lg bg-white border border-slate-200 space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-slate-900">{t.name}</span>
                              <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-medium ${
                                t.is_outdated ? 'bg-rose-100 text-rose-800' : 'bg-slate-100 text-slate-700'
                              }`}>
                                {t.lifecycle_status}
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-500">
                              Version: <span className="font-mono text-slate-800 font-semibold">{t.version}</span>
                            </div>
                            <div className="text-[10px] text-slate-400 font-mono truncate">
                              Evidence: {t.evidence}
                            </div>
                            {t.advisory && (
                              <div className="text-[11px] text-rose-700 pt-1">
                                {t.advisory}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Category 5: CVE Vulnerabilities */}
                  {cat.category_id === 'KNOWN_VULNERABILITIES' && ev.vulnerabilities && (
                    <div className="space-y-2">
                      <span className="font-semibold text-slate-800 block">Correlated NVD CVE Records:</span>
                      {ev.vulnerabilities.length === 0 ? (
                        <div className="p-3 rounded-lg bg-white border border-slate-200 text-slate-500">
                          No known CVEs matched against identified software versions.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {ev.vulnerabilities.map((v, vi) => (
                            <div key={vi} className="p-3 rounded-lg bg-white border border-slate-200 space-y-1">
                              <div className="flex items-center justify-between flex-wrap gap-2">
                                <div className="flex items-center gap-2">
                                  <span className="font-bold font-mono text-rose-700">{v.cve_id}</span>
                                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-50 text-rose-800 border border-rose-200">
                                    CVSS {v.cvss_score} • {v.severity}
                                  </span>
                                </div>
                                <a
                                  href={v.reference_url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-[11px] text-slate-700 hover:text-slate-900 underline flex items-center gap-1 font-mono"
                                >
                                  <span>NVD Reference</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </div>
                              <div className="text-xs font-semibold text-slate-900">{v.title}</div>
                              <p className="text-xs text-slate-600 leading-relaxed">{v.description}</p>
                              <div className="text-[11px] text-slate-500 font-mono">
                                Affected: {v.affected_range} • Detected: {v.detected_version} ({v.match_status})
                              </div>
                              {v.caveat && (
                                <div className="text-[11px] text-amber-800 bg-amber-50/70 p-2 rounded border border-amber-200">
                                  <span className="font-semibold">Defensive Caveat:</span> {v.caveat}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Category 7: HTTP Security Headers */}
                  {cat.category_id === 'HTTP_SECURITY_HEADERS' && ev.header_checks && (
                    <div className="space-y-2">
                      <span className="font-semibold text-slate-800 block">Security Header Evaluation Checklist:</span>
                      <div className="space-y-1.5">
                        {ev.header_checks.map((h, hi) => {
                          const isOpt = h.status === 'OPTIMAL'
                          const isWarn = h.status === 'WARNING'
                          return (
                            <div
                              key={hi}
                              className="p-2.5 rounded-lg bg-white border border-slate-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2"
                            >
                              <div className="space-y-0.5">
                                <div className="flex items-center gap-2">
                                  <span className={`w-2 h-2 rounded-full ${isOpt ? 'bg-emerald-500' : isWarn ? 'bg-amber-500' : 'bg-rose-500'}`} />
                                  <span className="font-bold font-mono text-slate-900">{h.header}</span>
                                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                                    isOpt ? 'bg-emerald-50 text-emerald-800 border-emerald-200' : isWarn ? 'bg-amber-50 text-amber-800 border-amber-200' : 'bg-rose-50 text-rose-800 border-rose-200'
                                  }`}>
                                    {h.status}
                                  </span>
                                </div>
                                <div className="text-[11px] text-slate-600">{h.finding}</div>
                              </div>
                              {h.value && (
                                <span className="text-[10px] font-mono text-slate-400 truncate max-w-xs self-start sm:self-auto bg-slate-50 px-2 py-1 rounded border border-slate-100">
                                  {h.value}
                                </span>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  {/* Category 8: Domain & DNS Records */}
                  {cat.category_id === 'DOMAIN_REGISTRATION_AND_DNS' && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-[11px]">
                      <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1 text-slate-700">
                        <span className="font-sans font-bold text-slate-900 text-xs block mb-1">Registration Details:</span>
                        <div>Created: <span className="text-slate-900 font-semibold">{ev.creation_date || 'Unknown'}</span></div>
                        <div>Domain Age: <span className="text-slate-900 font-semibold">{ev.domain_age_days ? `${ev.domain_age_days} days` : 'N/A'}</span></div>
                        <div>Registrar: <span className="text-slate-900">{ev.registrar || 'Privacy-Protected'}</span></div>
                        <div>Expires: <span className="text-slate-900">{ev.expiry_date || 'N/A'}</span></div>
                      </div>
                      <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1 text-slate-700">
                        <span className="font-sans font-bold text-slate-900 text-xs block mb-1">DNS Security Records:</span>
                        <div className="flex items-center gap-2">
                          <span>SPF Record:</span>
                          <span className={ev.has_spf ? 'text-emerald-700 font-bold' : 'text-amber-700'}>{ev.has_spf ? 'Enabled' : 'Missing'}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span>DMARC Record:</span>
                          <span className={ev.has_dmarc ? 'text-emerald-700 font-bold' : 'text-rose-700'}>{ev.has_dmarc ? 'Enabled' : 'Missing'}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span>DNSSEC:</span>
                          <span className={ev.dnssec_enabled ? 'text-emerald-700 font-bold' : 'text-slate-500'}>{ev.dnssec_enabled ? 'Active' : 'Unsigned'}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Category 10: Broken Resources & Errors */}
                  {cat.category_id === 'WEBSITE_HEALTH_AND_AVAILABILITY' && ev.broken_resources && ev.broken_resources.length > 0 && (
                    <div className="space-y-2">
                      <span className="font-semibold text-rose-800 block">Broken Asset Requests (404/500 Errors):</span>
                      <div className="space-y-1.5 font-mono text-[11px]">
                        {ev.broken_resources.map((br, bri) => (
                          <div key={bri} className="p-2.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-900 flex justify-between items-center gap-2">
                            <span className="truncate">{br.asset_type}: {br.asset_url}</span>
                            <span className="font-bold px-2 py-0.5 rounded bg-rose-200 text-rose-900 shrink-0">HTTP {br.http_status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Raw Technical JSON dump toggle for security engineers */}
                  <details className="mt-2 text-[11px] text-slate-500">
                    <summary className="cursor-pointer hover:text-slate-800 select-none">
                      Inspect Raw JSON Evidence Payload
                    </summary>
                    <pre className="mt-2 p-3 rounded-lg bg-slate-900 text-slate-200 font-mono text-[10px] overflow-x-auto max-h-48 border border-slate-800">
                      {JSON.stringify(ev, null, 2)}
                    </pre>
                  </details>

                </div>
              )}
            </div>
          )
        })}
      </div>

    </div>
  )
}
