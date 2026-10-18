import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { getMe, getUserProfile, getUserAlerts, logoutUser } from '../utils/api'

const AuthContext = createContext(null)

export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(() => localStorage.getItem('phishsense_token'))
  const [isLoading, setIsLoading] = useState(true)
  const [unreadAlertsCount, setUnreadAlertsCount] = useState(0)
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false)
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false)

  // Verify JWT expiration locally
  const isTokenExpired = (jwtToken) => {
    try {
      if (!jwtToken) return true
      const parts = jwtToken.split('.')
      if (parts.length !== 3) return true
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
      if (payload.exp && Date.now() >= payload.exp * 1000) {
        return true
      }
      return false
    } catch {
      return true
    }
  }

  const logout = useCallback(async () => {
    try {
      await logoutUser()
    } catch {
      // Ignore network errors on logout
    }
    localStorage.removeItem('phishsense_token')
    setToken(null)
    setUser(null)
    setUnreadAlertsCount(0)
    setIsProfileModalOpen(false)
  }, [])

  // Refresh user profile and alert count
  const refreshUser = useCallback(async () => {
    const currentToken = localStorage.getItem('phishsense_token')
    if (!currentToken || isTokenExpired(currentToken)) {
      logout()
      setIsLoading(false)
      return
    }

    try {
      const profileData = await getUserProfile()
      if (profileData && profileData.user) {
        setUser(profileData.user)
        setUnreadAlertsCount(profileData.unreadAlerts || 0)
      } else {
        // Fallback to /api/auth/me
        const me = await getMe()
        if (me && me.id) {
          setUser(me)
          const alertRes = await getUserAlerts()
          if (alertRes) setUnreadAlertsCount(alertRes.unreadCount || 0)
        } else {
          logout()
        }
      }
    } catch (e) {
      console.warn('Failed to load user session:', e)
    } finally {
      setIsLoading(false)
    }
  }, [logout])

  // Login handler
  const loginWithToken = useCallback((newToken, newUser) => {
    localStorage.setItem('phishsense_token', newToken)
    setToken(newToken)
    setUser(newUser)
    setIsAuthModalOpen(false)
    // Fetch fresh alerts
    getUserAlerts().then((res) => {
      if (res) setUnreadAlertsCount(res.unreadCount || 0)
    })
  }, [])

  // Initial authentication check
  useEffect(() => {
    refreshUser()

    const handleUnauthorized = () => {
      logout()
    }
    window.addEventListener('phishsense:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('phishsense:unauthorized', handleUnauthorized)
  }, [refreshUser, logout])

  // Polling for security alerts every 45s if authenticated
  useEffect(() => {
    if (!user) return
    const interval = setInterval(() => {
      getUserAlerts().then((res) => {
        if (res && typeof res.unreadCount === 'number') {
          setUnreadAlertsCount(res.unreadCount)
        }
      })
    }, 45000)
    return () => clearInterval(interval)
  }, [user])

  const openAuthModal = () => setIsAuthModalOpen(true)
  const closeAuthModal = () => setIsAuthModalOpen(false)
  const openProfileModal = () => setIsProfileModalOpen(true)
  const closeProfileModal = () => setIsProfileModalOpen(false)

  const value = {
    user,
    token,
    isAuthenticated: !!user,
    isLoading,
    unreadAlertsCount,
    setUnreadAlertsCount,
    loginWithToken,
    logout,
    refreshUser,
    isAuthModalOpen,
    openAuthModal,
    closeAuthModal,
    isProfileModalOpen,
    openProfileModal,
    closeProfileModal,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
