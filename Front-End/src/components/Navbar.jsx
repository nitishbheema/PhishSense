import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, ScanLine, LogIn, LogOut, Bell, User as UserIcon, ExternalLink } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const location = useLocation()
  const { isAuthenticated, user, openAuthModal, openProfileModal, logout, unreadAlertsCount } = useAuth()

  const links = [
    { to: '/scan',      label: 'Threat Scanner', icon: ScanLine },
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  ]

  return (
    <nav className="sticky top-0 z-50 bg-white/90 backdrop-blur-md border-b border-slate-200 transition-all">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Brand */}
        <div className="flex items-center gap-6">
          <Link to="/" className="flex items-center gap-2.5 text-decoration-none">
            <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-sm">
              <Shield className="w-4 h-4" />
            </div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-base tracking-tight text-slate-900">
                PhishSense
              </span>
              <span className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                v3.5
              </span>
            </div>
          </Link>

          {/* Engine Status Pill */}
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Threat Radar Active</span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-1">
          {links.map(({ to, label, icon: Icon }) => {
            const isActive = location.pathname === to
            return (
              <Link
                key={to}
                to={to}
                className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-slate-100 text-slate-900 font-semibold'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                }`}
              >
                <Icon className="w-4 h-4 text-slate-500" />
                <span>{label}</span>
              </Link>
            )
          })}

          <Link
            to="/phishing-demo"
            className="hidden md:flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-500 hover:text-slate-900 hover:bg-slate-50 border border-slate-200 ml-2"
          >
            <span>Phishing Demo</span>
            <ExternalLink className="w-3 h-3 text-slate-400" />
          </Link>
        </div>

        {/* Right Actions & Profile */}
        <div className="flex items-center gap-2">
          {isAuthenticated ? (
            <>
              {/* Notification Bell */}
              <button
                onClick={openProfileModal}
                title="Security Alerts"
                className="relative p-2 rounded-lg text-slate-500 hover:text-slate-800 hover:bg-slate-100 border border-slate-200 transition-colors"
              >
                <Bell className="w-4 h-4" />
                {unreadAlertsCount > 0 && (
                  <span className="absolute -top-1 -right-1 bg-rose-500 text-white text-[10px] font-bold w-4 h-4 rounded-full flex items-center justify-center">
                    {unreadAlertsCount}
                  </span>
                )}
              </button>

              {/* User Account Pill */}
              <button
                onClick={openProfileModal}
                title="View Profile & Detection History"
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-sm font-medium transition-colors"
              >
                {user?.avatarUrl ? (
                  <img
                    src={user.avatarUrl}
                    alt={user.fullName || 'User'}
                    className="w-5 h-5 rounded-full"
                  />
                ) : (
                  <div className="w-5 h-5 rounded-full bg-slate-900 text-white text-[10px] font-semibold flex items-center justify-center">
                    {(user?.fullName || user?.email || 'U')[0].toUpperCase()}
                  </div>
                )}
                <span className="max-w-[120px] truncate">
                  {user?.fullName || user?.email?.split('@')[0] || 'My Account'}
                </span>
              </button>

              {/* Logout Button */}
              <button
                onClick={logout}
                title="Sign out of personal session"
                className="p-2 rounded-lg text-slate-500 hover:text-rose-600 hover:bg-slate-100 transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={openAuthModal}
              className="btn-primary text-xs sm:text-sm cursor-pointer"
            >
              Sign In
            </button>
          )}
        </div>

      </div>
    </nav>
  )
}
