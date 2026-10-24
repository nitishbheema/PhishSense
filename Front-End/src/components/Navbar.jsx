import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, ScanLine, LogIn, LogOut, Bell, User as UserIcon } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const location = useLocation()
  const { isAuthenticated, user, openAuthModal, openProfileModal, logout, unreadAlertsCount } = useAuth()

  const links = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/scan',      label: 'Threat Scanner', icon: ScanLine    },
  ]

  return (
    <nav style={{
      background: '#0f0f1a',
      borderBottom: '1px solid #1e1e2e',
      padding: '0 2rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      height: '60px',
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', textDecoration: 'none' }}>
        <Shield size={22} color="#6366f1" />
        <span style={{ fontWeight: 700, fontSize: '15px', color: '#e8e8f0', letterSpacing: '-0.3px' }}>
          PhishSense
        </span>
        <span style={{
          fontSize: '10px', background: '#1e1e3a', color: '#818cf8',
          border: '1px solid #2a2a50', borderRadius: '4px',
          padding: '2px 7px', fontWeight: 500, letterSpacing: '0.3px',
        }}>
          v3.5
        </span>
      </Link>

      <div style={{ display: 'flex', gap: '4px' }}>
        {links.map(({ to, label, icon: Icon }) => (
          <Link key={to} to={to} style={{
            display: 'flex', alignItems: 'center', gap: '6px',
            padding: '6px 14px', borderRadius: '8px',
            textDecoration: 'none', fontSize: '14px',
            background: location.pathname === to ? '#1e1e3a' : 'transparent',
            color: location.pathname === to ? '#818cf8' : '#888',
            transition: 'all 0.15s',
          }}>
            <Icon size={15} />
            {label}
          </Link>
        ))}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {isAuthenticated ? (
          <>
            {/* Security Alerts Bell */}
            <button
              onClick={openProfileModal}
              title="Security Alerts"
              style={{
                position: 'relative',
                background: '#131b2e',
                border: '1px solid #222f49',
                borderRadius: '8px',
                padding: '7px 9px',
                color: unreadAlertsCount > 0 ? '#ef4444' : '#94a3b8',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.15s',
              }}
            >
              <Bell size={16} />
              {unreadAlertsCount > 0 && (
                <span style={{
                  position: 'absolute',
                  top: '-4px',
                  right: '-4px',
                  background: '#ef4444',
                  color: '#fff',
                  fontSize: '9px',
                  fontWeight: 700,
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 8px rgba(239, 68, 68, 0.6)',
                }}>
                  {unreadAlertsCount}
                </span>
              )}
            </button>

            {/* User Profile Chip */}
            <button
              onClick={openProfileModal}
              title="View Profile & Detection History"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: '#141829',
                border: '1px solid #28334e',
                borderRadius: '8px',
                padding: '5px 12px',
                color: '#e2e8f0',
                fontSize: '13px',
                fontWeight: 500,
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              {user?.avatarUrl ? (
                <img
                  src={user.avatarUrl}
                  alt={user.fullName || 'User'}
                  style={{ width: '22px', height: '22px', borderRadius: '50%' }}
                />
              ) : (
                <div style={{
                  width: '22px', height: '22px', borderRadius: '50%',
                  background: '#6366f1', color: '#fff', fontSize: '11px',
                  fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {(user?.fullName || user?.email || 'U')[0].toUpperCase()}
                </div>
              )}
              <span style={{ maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user?.fullName || user?.email?.split('@')[0] || 'User'}
              </span>
            </button>

            {/* Logout */}
            <button
              onClick={logout}
              title="Secure Logout"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                background: 'transparent',
                border: '1px solid #1e1e2e',
                borderRadius: '8px',
                padding: '6px 12px',
                color: '#888',
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              <LogOut size={14} />
              Logout
            </button>
          </>
        ) : (
          <button
            onClick={openAuthModal}
            title="Sign in only if you want to track personal scans"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'linear-gradient(135deg, #6366f1, #4f46e5)',
              border: 'none',
              borderRadius: '8px',
              padding: '7px 16px',
              color: '#ffffff',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 2px 10px rgba(99,102,241,0.3)',
              transition: 'all 0.15s',
            }}
          >
            <LogIn size={14} />
            Sign In to Track
          </button>
        )}
      </div>
    </nav>
  )
}
