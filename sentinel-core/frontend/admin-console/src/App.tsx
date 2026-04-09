import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate, Link } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Login } from './pages/Login'
import { useAuthStore } from './store/authStore'
import { appConfig } from './config/runtime'

const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })))
const Threats = lazy(() => import('./pages/Threats').then(m => ({ default: m.Threats })))
const ThreatDetail = lazy(() => import('./pages/ThreatDetail').then(m => ({ default: m.ThreatDetail })))
const Policies = lazy(() => import('./pages/Policies').then(m => ({ default: m.Policies })))
const Compliance = lazy(() => import('./pages/Compliance').then(m => ({ default: m.Compliance })))
const Alerts = lazy(() => import('./pages/Alerts').then(m => ({ default: m.Alerts })))
const Hardening = lazy(() => import('./pages/Hardening').then(m => ({ default: m.Hardening })))
const HidsEvents = lazy(() => import('./pages/HidsEvents').then(m => ({ default: m.HidsEvents })))
const Users = lazy(() => import('./pages/Users').then(m => ({ default: m.Users })))
const AuditLog = lazy(() => import('./pages/AuditLog').then(m => ({ default: m.AuditLog })))
const Tenants = lazy(() => import('./pages/Tenants').then(m => ({ default: m.Tenants })))
const MfaSetup = lazy(() => import('./pages/MfaSetup').then(m => ({ default: m.MfaSetup })))
const SiemConfig = lazy(() => import('./pages/SiemConfig').then(m => ({ default: m.SiemConfig })))
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })))

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
      <Suspense fallback={<div className="flex items-center justify-center h-64 text-slate-400">Loading…</div>}>
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
          <Route path="/tenants" element={<Tenants />} />
          <Route path="/mfa-setup" element={<MfaSetup />} />
          <Route path="/siem" element={<SiemConfig />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </Layout>
  )
}

export default App
