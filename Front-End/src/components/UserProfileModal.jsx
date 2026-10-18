import React, { useState, useEffect } from 'react'
import { useAuth } from '../context/AuthContext'
import { getUserProfile, getUserScans, getUserAlerts, acknowledgeAlert, acknowledgeAllAlerts } from '../utils/api'
import {
  Shield, User as UserIcon, History, Bell, LogOut, CheckCircle2,
  AlertTriangle, ShieldAlert, Info, ExternalLink, Calendar, Laptop, RefreshCw, X, Check
} from 'lucide-react'

export default function UserProfileModal() {
  const {
    isProfileModalOpen, closeProfileModal, user, logout,
    unreadAlertsCount, setUnreadAlertsCount
  } = useAuth()

  const [activeTab, setActiveTab] = useState('PROFILE') // 'PROFILE' | 'SCANS' | 'ALERTS'
  const [profileData, setProfileData] = useState(null)
  const [scans, setScans] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(false)

  // Load data when opened or tab changed
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
    if (score >= 65) return '#ef4444'
    if (score >= 35) return '#f59e0b'
    return '#10b981'
  }

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return { bg: 'rgba(239, 68, 68, 0.15)', text: '#f87171', border: '#ef4444', icon: ShieldAlert }
      case 'HIGH':
        return { bg: 'rgba(249, 115, 22, 0.15)', text: '#fb923c', border: '#f97316', icon: AlertTriangle }
      case 'WARNING':
        return { bg: 'rgba(245, 158, 11, 0.15)', text: '#fbbf24', border: '#f59e0b', icon: AlertTriangle }
      default:
        return { bg: 'rgba(56, 189, 248, 0.15)', text: '#38bdf8', border: '#0284c7', icon: Info }
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(5, 7, 15, 0.82)', backdropFilter: 'blur(8px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1.5rem',
    }}>
      <div style={{
        background: '#0d111e',
        border: '1px solid #1f293d',
        borderRadius: '16px',
        width: '100%',
        maxWidth: '720px',
        maxHeight: '85vh',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 25px 60px -15px rgba(0,0,0,0.7), 0 0 35px rgba(99,102,241,0.12)',
        overflow: 'hidden',
        animation: 'fadeIn 0.2s ease-out',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid #172033',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {user.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.fullName || 'User'}
                style={{ width: '44px', height: '44px', borderRadius: '50%', border: '2px solid #6366f1' }}
              />
            ) : (
              <div style={{
                width: '44px', height: '44px', borderRadius: '50%',
                background: 'linear-gradient(135deg, #6366f1, #3b82f6)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#fff', fontWeight: 700, fontSize: '18px',
              }}>
                {(user.fullName || user.email || 'U')[0].toUpperCase()}
              </div>
            )}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 600, color: '#f1f5f9' }}>
                  {user.fullName || 'User Profile'}
                </h3>
                <span style={{
                  fontSize: '11px', background: 'rgba(99, 102, 241, 0.15)',
                  color: '#818cf8', border: '1px solid rgba(99, 102, 241, 0.3)',
                  padding: '2px 8px', borderRadius: '12px', fontWeight: 500,
                }}>
                  {user.authProvider === 'GOOGLE' ? 'Google OAuth' : 'Email OTP'}
                </span>
                {user.emailVerified && (
                  <span title="Verified Account" style={{ display: 'flex', alignItems: 'center', color: '#10b981' }}>
                    <CheckCircle2 size={16} />
                  </span>
                )}
              </div>
              <p style={{ margin: '2px 0 0', fontSize: '13px', color: '#64748b' }}>
                {user.email}
              </p>
            </div>
          </div>

          <button
            onClick={closeProfileModal}
            style={{
              background: 'transparent', border: 'none', color: '#64748b',
              cursor: 'pointer', padding: '6px', borderRadius: '6px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div style={{
          display: 'flex', gap: '8px', padding: '0 24px',
          borderBottom: '1px solid #172033', background: '#090d18',
        }}>
          {[
            { id: 'PROFILE', label: 'Account Profile', icon: UserIcon },
            { id: 'SCANS', label: 'My Scan History', icon: History, count: profileData?.scanCount },
            { id: 'ALERTS', label: 'Security Alerts', icon: Bell, badge: unreadAlertsCount },
          ].map(({ id, label, icon: Icon, badge, count }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                padding: '12px 14px',
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === id ? '2px solid #6366f1' : '2px solid transparent',
                color: activeTab === id ? '#818cf8' : '#64748b',
                fontWeight: activeTab === id ? 600 : 500,
                fontSize: '13.5px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <Icon size={16} />
              {label}
              {typeof count === 'number' && count > 0 && (
                <span style={{
                  fontSize: '11px', background: '#1e293b', color: '#94a3b8',
                  padding: '1px 6px', borderRadius: '10px',
                }}>
                  {count}
                </span>
              )}
              {typeof badge === 'number' && badge > 0 && (
                <span style={{
                  fontSize: '10px', background: '#ef4444', color: '#fff',
                  padding: '1px 6px', borderRadius: '10px', fontWeight: 700,
                }}>
                  {badge}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content (Scrollable) */}
        <div style={{ padding: '24px', overflowY: 'auto', flex: 1 }}>
          {loading && (
            <div style={{ display: 'flex', justifyContent: 'center', padding: '30px', color: '#818cf8' }}>
              <RefreshCw size={24} className="animate-spin" />
            </div>
          )}

          {!loading && activeTab === 'PROFILE' && (
            <div>
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '14px', marginBottom: '24px',
              }}>
                <div style={{ background: '#131b2e', border: '1px solid #1f293d', borderRadius: '10px', padding: '16px' }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>Total Scans Logged</div>
                  <div style={{ fontSize: '24px', fontWeight: 700, color: '#f8fafc' }}>
                    {profileData?.scanCount ?? 0}
                  </div>
                </div>
                <div style={{ background: '#131b2e', border: '1px solid #1f293d', borderRadius: '10px', padding: '16px' }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>Active Security Alerts</div>
                  <div style={{ fontSize: '24px', fontWeight: 700, color: unreadAlertsCount > 0 ? '#ef4444' : '#10b981' }}>
                    {unreadAlertsCount}
                  </div>
                </div>
                <div style={{ background: '#131b2e', border: '1px solid #1f293d', borderRadius: '10px', padding: '16px' }}>
                  <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>Security Rating</div>
                  <div style={{ fontSize: '24px', fontWeight: 700, color: '#38bdf8' }}>
                    {unreadAlertsCount > 0 ? 'Review Needed' : 'Protected'}
                  </div>
                </div>
              </div>

              {/* Details List */}
              <div style={{
                background: '#101626', border: '1px solid #1e293b',
                borderRadius: '12px', padding: '18px', marginBottom: '24px',
              }}>
                <h4 style={{ margin: '0 0 14px', fontSize: '14px', color: '#cbd5e1', fontWeight: 600 }}>
                  Session & Audit Information
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #172033', paddingBottom: '8px' }}>
                    <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Calendar size={14} /> Member Since
                    </span>
                    <span style={{ color: '#cbd5e1' }}>
                      {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Active'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #172033', paddingBottom: '8px' }}>
                    <span style={{ color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Laptop size={14} /> Last Login IP
                    </span>
                    <span style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>
                      {user.lastLoginIp || '127.0.0.1'}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#64748b' }}>Account Access Level</span>
                    <span style={{ color: '#10b981', fontWeight: 500 }}>
                      Standard Platform User (Unified)
                    </span>
                  </div>
                </div>
              </div>

              {/* Secure Logout CTA */}
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  onClick={logout}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '8px',
                    padding: '10px 18px', borderRadius: '8px',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#f87171', fontSize: '13.5px', fontWeight: 500,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  <LogOut size={16} />
                  Secure Sign Out
                </button>
              </div>
            </div>
          )}

          {!loading && activeTab === 'SCANS' && (
            <div>
              {scans.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b' }}>
                  <History size={36} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
                  <p style={{ margin: '0 0 6px', fontSize: '15px', color: '#94a3b8' }}>No scans recorded yet</p>
                  <p style={{ margin: 0, fontSize: '13px' }}>Scans you perform while signed in will appear here automatically.</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {scans.map((scan) => (
                    <div
                      key={scan.id}
                      style={{
                        background: '#131b2e', border: '1px solid #1f293d',
                        borderRadius: '10px', padding: '14px 16px',
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      }}
                    >
                      <div style={{ minWidth: 0, flex: 1, marginRight: '16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                          <span style={{
                            fontSize: '11px', background: '#1e293b', color: '#818cf8',
                            padding: '2px 6px', borderRadius: '4px', fontWeight: 600,
                          }}>
                            {scan.inputType || 'URL'}
                          </span>
                          <span style={{
                            fontSize: '11px', padding: '2px 8px', borderRadius: '10px',
                            fontWeight: 600,
                            background: `${getScoreColor(scan.threatScore)}22`,
                            color: getScoreColor(scan.threatScore),
                            border: `1px solid ${getScoreColor(scan.threatScore)}44`,
                          }}>
                            {scan.threatType} ({scan.threatScore}/100)
                          </span>
                        </div>
                        <div style={{
                          fontSize: '13.5px', color: '#f1f5f9', fontWeight: 500,
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>
                          {scan.url}
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b', marginTop: '4px' }}>
                          {new Date(scan.detectedAt).toLocaleString()} • Sector: {scan.threatCategory || 'General'}
                        </div>
                      </div>

                      {scan.blockHash && (
                        <div style={{
                          fontSize: '11px', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.1)',
                          border: '1px solid rgba(56, 189, 248, 0.25)', padding: '4px 8px',
                          borderRadius: '6px', fontFamily: 'monospace',
                        }}>
                          ⛓️ On-Chain
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {!loading && activeTab === 'ALERTS' && (
            <div>
              <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: '16px',
              }}>
                <span style={{ fontSize: '13px', color: '#94a3b8' }}>
                  {alerts.length} security notification{alerts.length !== 1 ? 's' : ''}
                </span>
                {unreadAlertsCount > 0 && (
                  <button
                    onClick={handleAckAllAlerts}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '6px',
                      background: 'transparent', border: '1px solid #2e3a54',
                      borderRadius: '6px', padding: '4px 10px',
                      color: '#818cf8', fontSize: '12px', cursor: 'pointer',
                    }}
                  >
                    <Check size={14} /> Mark all acknowledged
                  </button>
                )}
              </div>

              {alerts.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b' }}>
                  <Shield size={36} style={{ margin: '0 auto 12px', opacity: 0.5, color: '#10b981' }} />
                  <p style={{ margin: '0 0 6px', fontSize: '15px', color: '#94a3b8' }}>Account is secure</p>
                  <p style={{ margin: 0, fontSize: '13px' }}>No suspicious activity or high-risk threat alerts.</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {alerts.map((alert) => {
                    const badge = getSeverityBadge(alert.severity)
                    const IconComponent = badge.icon
                    return (
                      <div
                        key={alert.id}
                        style={{
                          background: alert.acknowledged ? '#111728' : '#161f36',
                          border: alert.acknowledged ? '1px solid #1f293d' : `1px solid ${badge.border}66`,
                          borderRadius: '10px', padding: '14px 16px',
                          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
                          gap: '12px',
                        }}
                      >
                        <div style={{ display: 'flex', gap: '12px' }}>
                          <div style={{
                            width: '32px', height: '32px', borderRadius: '8px',
                            background: badge.bg, border: `1px solid ${badge.border}44`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            color: badge.text, flexShrink: 0, marginTop: '2px',
                          }}>
                            <IconComponent size={16} />
                          </div>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                              <h5 style={{ margin: 0, fontSize: '14px', color: '#f1f5f9', fontWeight: 600 }}>
                                {alert.title}
                              </h5>
                              <span style={{
                                fontSize: '10px', background: badge.bg, color: badge.text,
                                padding: '1px 6px', borderRadius: '4px', fontWeight: 600,
                              }}>
                                {alert.severity}
                              </span>
                            </div>
                            <p style={{ margin: '0 0 6px', fontSize: '12.5px', color: '#94a3b8', lineHeight: 1.4 }}>
                              {alert.description}
                            </p>
                            <span style={{ fontSize: '11px', color: '#64748b' }}>
                              {new Date(alert.createdAt).toLocaleString()} {alert.ipAddress && `• IP: ${alert.ipAddress}`}
                            </span>
                          </div>
                        </div>

                        {!alert.acknowledged && (
                          <button
                            onClick={() => handleAckAlert(alert.id)}
                            title="Acknowledge alert"
                            style={{
                              background: '#1e293b', border: '1px solid #334155',
                              borderRadius: '6px', padding: '6px', color: '#94a3b8',
                              cursor: 'pointer', flexShrink: 0,
                            }}
                          >
                            <Check size={14} />
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
