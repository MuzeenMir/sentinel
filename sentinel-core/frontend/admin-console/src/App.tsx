import { useEffect } from 'react'
import { Routes, Route, Navigate, Link } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Threats } from './pages/Threats'
import { ThreatDetail } from './pages/ThreatDetail'
import { Policies } from './pages/Policies'
import { Compliance } from './pages/Compliance'
import { Settings } from './pages/Settings'
import { Login } from './pages/Login'
import { useAuthStore } from './store/authStore'
import { appConfig } from './config/runtime'

function App() {
  const { isAuthenticated } = useAuthStore()
  const demoEnabled = appConfig.demoAuth

  useEffect(() => {
    if (!isAuthenticated && demoEnabled) {
      useAuthStore
        .getState()
        .login('demo', 'demo-token')
        .catch(() => useAuthStore.getState().setDemoBypass())
    }
  }, [demoEnabled, isAuthenticated])

  if (!isAuthenticated && !demoEnabled) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="*"
          element={
            <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
              <div className="card max-w-md w-full p-6 space-y-4">
                <div>
                  <h1 className="text-xl font-semibold">Sign-in required</h1>
                  <p className="text-sm text-slate-400 mt-2">
                    Demo access is disabled for this environment. Configure authentication or enable
                    demo mode to continue.
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800/80 bg-slate-900/60 px-4 py-3 text-sm text-slate-300">
                  <p className="font-medium text-slate-200">Next steps</p>
                  <p className="mt-1">
                    Set <span className="font-mono">VITE_DEMO_AUTH=true</span> for local demos, or
                    connect your SSO provider and auth service.
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
        <Route path="/policies" element={<Policies />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default App
