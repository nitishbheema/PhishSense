import React, { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { getUserProfile, getUserScans, getUserAlerts, acknowledgeAlert, acknowledgeAllAlerts } from '../utils/api'
import {
  Shield, User as UserIcon, History, Bell, LogOut, CheckCircle2,
  AlertTriangle, ShieldAlert, Info, ExternalLink, Calendar, Laptop, RefreshCw, X, Check, Copy
} from 'lucide-react'

export default function UserProfileModal() {
  const {
    isProfileModalOpen, closeProfileModal, user, logout,
    unreadAlertsCount, setUnreadAlertsCount
  } = useAuth()

  const [activeTab, setActiveTab] = useState('PROFILE')
  const [profileData, setProfileData] = useState(null)
  const [scans, setScans] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!isProfileModalOpen || !user) return

    const fetchData = async () => {
      setLoading(true)
      try {
        if (activeTab === 'PROFILE') {
          const res = await getUserProfile()
          if (res) setProfileData(res)
        } else if (activeTab === 'SCANS') {
          const scanList = await getUserScans()
          if (Array.isArray(scanList)) setScans(scanList)
        } else if (activeTab === 'ALERTS') {
          const alertRes = await getUserAlerts()
          if (alertRes) {
            setAlerts(alertRes.alerts || [])
            setUnreadAlertsCount(alertRes.unreadCount || 0)
          }
        }
      } catch (err) {
        console.warn('Failed to load user modal data:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [isProfileModalOpen, activeTab, user, setUnreadAlertsCount])

  if (!isProfileModalOpen || !user) return null

  const handleAckAlert = async (id) => {
    await acknowledgeAlert(id)
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)))
    setUnreadAlertsCount((c) => Math.max(0, c - 1))
  }

  const handleAckAllAlerts = async () => {
    await acknowledgeAllAlerts()
    setAlerts((prev) => prev.map((a) => ({ ...a, acknowledged: true })))
    setUnreadAlertsCount(0)
  }

  const getScoreColor = (score) => {
    if (score >= 65) return '#e11d48'
    if (score >= 35) return '#d97706'
    return '#059669'
  }

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return { bg: 'bg-rose-50', text: 'text-rose-700', border: 'border-rose-200', icon: ShieldAlert }
      case 'HIGH':
        return { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', icon: AlertTriangle }
      case 'WARNING':
        return { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', icon: AlertTriangle }
      default:
        return { bg: 'bg-slate-50', text: 'text-slate-700', border: 'border-slate-200', icon: Info }
    }
  }

  return (
    <div className="fixed inset-0 z-[1000] bg-slate-900/40 backdrop-blur-sm flex items-center justify-center p-4 sm:p-6 animate-in fade-in duration-150">
      <div className="human-card w-full max-w-2xl max-h-[85vh] flex flex-col bg-white shadow-xl overflow-hidden border border-slate-200">
        
        {/* Header */}
        <div className="p-5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {user.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.fullName || 'User'}
                className="w-10 h-10 rounded-full"
              />
            ) : (
              <div className="w-10 h-10 rounded-full bg-slate-900 text-white flex items-center justify-center font-semibold text-sm">
                {(user.fullName || user.email || 'U')[0].toUpperCase()}
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-slate-900 m-0">
                  {user.fullName || 'User Account'}
                </h3>
                <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                  {user.authProvider === 'GOOGLE' ? 'Google' : 'Local'}
                </span>
                {user.emailVerified && (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" title="Verified Account" />
                )}
              </div>
              <p className="text-xs text-slate-500 m-0 mt-0.5">
                {user.email}
              </p>
            </div>
          </div>

          <button
            onClick={closeProfileModal}
            className="p-1 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 px-5 pt-2 border-b border-slate-200 bg-slate-50">
          {[
            { id: 'PROFILE', label: 'Overview', icon: UserIcon },
            { id: 'SCANS', label: 'My Scans', icon: History, count: profileData?.scanCount },
            { id: 'ALERTS', label: 'Security Alerts', icon: Bell, badge: unreadAlertsCount },
          ].map(({ id, label, icon: Icon, badge, count }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-1.5 py-2 px-3 text-xs sm:text-sm font-medium border-b-2 transition-all cursor-pointer ${
                activeTab === id
                  ? 'border-slate-900 text-slate-900 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{label}</span>
              {typeof count === 'number' && count > 0 && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-slate-200 text-slate-700 font-mono">
                  {count}
                </span>
              )}
              {typeof badge === 'number' && badge > 0 && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-rose-500 text-white font-bold">
                  {badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="p-5 overflow-y-auto flex-1 space-y-5">
          {loading && (
            <div className="flex justify-center py-10 text-slate-500">
              <RefreshCw className="w-5 h-5 animate-spin" />
            </div>
          )}

          {!loading && activeTab === 'PROFILE' && (
            <div className="space-y-5">
              {/* Stat Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-0.5">
                  <span className="text-xs text-slate-500 font-medium">Total Scans</span>
                  <div className="text-xl font-bold text-slate-900 font-mono">
                    {profileData?.scanCount ?? 0}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-0.5">
                  <span className="text-xs text-slate-500 font-medium">Active Alerts</span>
                  <div className={`text-xl font-bold font-mono ${unreadAlertsCount > 0 ? 'text-rose-600' : 'text-emerald-600'}`}>
                    {unreadAlertsCount}
                  </div>
                </div>
                <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-0.5">
                  <span className="text-xs text-slate-500 font-medium">Account Status</span>
                  <div className="text-sm font-semibold text-emerald-700 mt-1">
                    Protected
                  </div>
                </div>
              </div>

              {/* Session Details */}
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2 text-xs">
                <h4 className="font-semibold text-slate-800">Session & Protection Details</h4>
                <div className="divide-y divide-slate-200">
                  <div className="py-2 flex justify-between">
                    <span className="text-slate-500 flex items-center gap-1.5">
                      <Calendar className="w-3.5 h-3.5 text-slate-600" /> Member Since
                    </span>
                    <span className="text-slate-800 font-medium">
                      {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Active Session'}
                    </span>
                  </div>
                  <div className="py-2 flex justify-between">
                    <span className="text-slate-500 flex items-center gap-1.5">
                      <Laptop className="w-3.5 h-3.5 text-slate-600" /> Last Recorded IP
                    </span>
                    <span className="text-slate-800 font-mono">
                      {user.lastLoginIp || '127.0.0.1'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-1">
                <button
                  onClick={logout}
                  className="btn-secondary px-3.5 py-1.5 text-xs text-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  <LogOut className="w-3.5 h-3.5 text-slate-500" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}

          {!loading && activeTab === 'SCANS' && (
            <div>
              {scans.length === 0 ? (
                <div className="text-center py-10 text-slate-400 space-y-1.5">
                  <History className="w-7 h-7 mx-auto opacity-40 text-slate-400" />
                  <p className="text-sm font-medium text-slate-700">No personal scans recorded yet</p>
                  <p className="text-xs">Scans you run while signed in are automatically organized here.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {scans.map((scan) => (
                    <div
                      key={scan.id}
                      className="p-3 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="truncate flex-1 space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-slate-700 bg-slate-200 px-1.5 py-0.2 rounded text-[10px]">
                            {scan.inputType || 'URL'}
                          </span>
                          <span
                            className="font-medium text-[10px] px-1.5 py-0.2 rounded font-mono"
                            style={{
                              color: getScoreColor(scan.threatScore),
                              backgroundColor: `${getScoreColor(scan.threatScore)}15`,
                            }}
                          >
                            {scan.threatType} ({scan.threatScore}%)
                          </span>
                        </div>
                        <div className="font-mono text-slate-800 truncate">{scan.url}</div>
                        <div className="text-[11px] text-slate-400">
                          {new Date(scan.detectedAt).toLocaleString()}
                        </div>
                      </div>
                      {scan.blockHash && (
                        <span className="text-[10px] font-mono text-slate-600 bg-slate-200 px-2 py-0.5 rounded shrink-0">
                          On-Chain
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!loading && activeTab === 'ALERTS' && (
            <div className="space-y-2.5">
              <div className="flex justify-between items-center text-xs text-slate-500">
                <span>{alerts.length} security notification{alerts.length !== 1 ? 's' : ''}</span>
                {unreadAlertsCount > 0 && (
                  <button
                    onClick={handleAckAllAlerts}
                    className="text-slate-900 underline font-medium cursor-pointer"
                  >
                    Mark all acknowledged
                  </button>
                )}
              </div>

              {alerts.length === 0 ? (
                <div className="text-center py-10 text-slate-400 space-y-1.5">
                  <ShieldCheck className="w-7 h-7 text-emerald-600 mx-auto" />
                  <p className="text-sm font-medium text-slate-700">No active threat alerts</p>
                  <p className="text-xs">Your account and inspected destinations are safe.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {alerts.map((alert) => {
                    const badge = getSeverityBadge(alert.severity)
                    const IconComponent = badge.icon
                    return (
                      <div
                        key={alert.id}
                        className="p-3 rounded-lg border border-slate-200 bg-slate-50 flex items-start justify-between gap-3 text-xs"
                      >
                        <div className="flex gap-2.5">
                          <div className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 ${badge.bg} ${badge.text}`}>
                            <IconComponent className="w-3.5 h-3.5" />
                          </div>
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-1.5">
                              <span className="font-medium text-slate-900">{alert.title}</span>
                              <span className={`text-[10px] font-semibold px-1.5 py-0.2 rounded ${badge.bg} ${badge.text}`}>
                                {alert.severity}
                              </span>
                            </div>
                            <p className="text-slate-600 leading-relaxed">{alert.description}</p>
                            <span className="text-[11px] text-slate-400 font-mono">
                              {new Date(alert.createdAt).toLocaleString()}
                            </span>
                          </div>
                        </div>

                        {!alert.acknowledged && (
                          <button
                            onClick={() => handleAckAlert(alert.id)}
                            className="p-1 rounded bg-white hover:bg-slate-100 text-slate-600 border border-slate-200 cursor-pointer"
                            title="Acknowledge alert"
                          >
                            <Check className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

        </div>

      </div>
    </div>
  )
}
