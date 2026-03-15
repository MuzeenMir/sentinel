import { Routes, Route, Navigate, Link } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Threats } from './pages/Threats'
import { ThreatDetail } from './pages/ThreatDetail'
import { Policies } from './pages/Policies'
import { Compliance } from './pages/Compliance'
import { Alerts } from './pages/Alerts'
import { Hardening } from './pages/Hardening'
import { HidsEvents } from './pages/HidsEvents'
import { Users } from './pages/Users'
import { AuditLog } from './pages/AuditLog'
import { Settings } from './pages/Settings'
import { Login } from './pages/Login'
import { useAuthStore } from './store/authStore'
import { appConfig } from './config/runtime'

function App() {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="*"
          element={
            <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
              <div className="card max-w-md w-full p-6 space-y-4">
                <div>
                  <h1 className="text-xl font-semibold">Authentication Required</h1>
                  <p className="text-sm text-slate-400 mt-2">
                    Please sign in with your credentials to access the SENTINEL dashboard.
                  </p>
                </div>
                <div className="flex justify-center">
                  <Link
                    to="/login"
                    className="inline-flex items-center justify-center px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium"
                  >
                    Sign in
                  </Link>
                </div>
                <p className="text-xs text-slate-500 text-center">
                  Need help? Contact {appConfig.supportEmail}.
                </p>
              </div>
            </div>
          }
        />
      </Routes>
    )
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/threats/:id" element={<ThreatDetail />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/hardening" element={<Hardening />} />
        <Route path="/hids" element={<HidsEvents />} />
        <Route path="/users" element={<Users />} />
        <Route path="/audit" element={<AuditLog />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default App
