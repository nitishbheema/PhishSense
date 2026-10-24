import { BrowserRouter, Routes, Route } from 'react-router-dom'
import LandingPage from './pages/LandingPage'
import LegitLogin from './pages/LegitLogin'
import PhishingLogin from './pages/PhishingLogin'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import Navbar from './components/Navbar'
import { AuthProvider } from './context/AuthContext'
import AuthModal from './components/AuthModal'
import UserProfileModal from './components/UserProfileModal'
export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<><LandingPage /><AuthModal /><UserProfileModal /></>} />
          <Route path="/legit-login" element={<LegitLogin />} />
          <Route path="/phishing-demo" element={<PhishingLogin />} />
          <Route path="/dashboard" element={<><Navbar /><Dashboard /><AuthModal /><UserProfileModal /></>} />
          <Route path="/scan" element={<><Navbar /><ScanPage /><AuthModal /><UserProfileModal /></>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

