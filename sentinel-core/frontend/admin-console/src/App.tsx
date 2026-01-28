import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Threats } from './pages/Threats'
import { ThreatDetail } from './pages/ThreatDetail'
import { Policies } from './pages/Policies'
import { Compliance } from './pages/Compliance'
import { Settings } from './pages/Settings'
import { useAuthStore } from './store/authStore'

function App() {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
    // For demo, auto-authenticate
    useAuthStore.getState().login('demo', 'demo-token')
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
