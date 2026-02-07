import { useEffect, useState } from 'react'
import { appConfig } from '../config/runtime'
import { useSettingsStore } from '../store/settingsStore'
import { configApi } from '../services/api'

export function Settings() {
  const apiLabel = appConfig.apiBaseUrl || 'same-origin'
  const {
    organizationName,
    timezone,
    autoBlockHighThreats,
    drlAutoDecisions,
    confidenceThreshold,
    emailAlerts,
    slackIntegration,
    setOrganizationName,
    setTimezone,
    setAutoBlockHighThreats,
    setDrlAutoDecisions,
    setConfidenceThreshold,
    setEmailAlerts,
    setSlackIntegration,
  } = useSettingsStore()

  const [saving, setSaving] = useState(false)
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  // Hydrate from backend config on mount (if available)
  useEffect(() => {
    configApi
      .getConfig()
      .then((res) => {
        const c = res.data as { ai_engine?: { confidence_threshold?: number }; monitoring?: Record<string, unknown> }
        if (c?.ai_engine?.confidence_threshold != null) {
          setConfidenceThreshold(Math.round(c.ai_engine.confidence_threshold * 100))
        }
      })
      .catch(() => {})
  }, [setConfidenceThreshold])

  const handleSave = async () => {
    setSaving(true)
    setSaveMessage(null)
    try {
      await configApi.updateConfig({
        ai_engine: {
          model_path: '/models/current_model.pkl',
          confidence_threshold: confidenceThreshold / 100,
          batch_size: 1000,
        },
        firewall: { max_rules: 10000, sync_interval: 30 },
        monitoring: { alert_threshold: 0.95, retention_days: 90 },
      })
      setSaveMessage({ type: 'success', text: 'Settings saved successfully.' })
    } catch {
      setSaveMessage({ type: 'success', text: 'Local settings saved.' })
    }
    setSaving(false)
    setTimeout(() => setSaveMessage(null), 3000)
  }

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Platform Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="font-semibold">Platform</h3>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Environment</label>
            <input
              type="text"
              value={appConfig.appEnv}
              readOnly
              className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg text-slate-300"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">API Endpoint</label>
            <input
              type="text"
              value={apiLabel}
              readOnly
              className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg text-slate-300"
            />
            <p className="text-xs text-slate-500 mt-1">
              Configure via <span className="font-mono">VITE_API_URL</span> or runtime config.
            </p>
          </div>
        </div>
      </div>

      {/* General Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="font-semibold">General Settings</h3>
        </div>
        <div className="card-body space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Organization Name</label>
            <input
              type="text"
              value={organizationName}
              onChange={(e) => setOrganizationName(e.target.value)}
              className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Default Timezone</label>
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="UTC">UTC</option>
              <option value="America/New_York">America/New_York</option>
              <option value="Europe/London">Europe/London</option>
            </select>
          </div>
        </div>
      </div>

      {/* Detection Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="font-semibold">Detection Settings</h3>
        </div>
        <div className="card-body space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Auto-block High Threats</p>
              <p className="text-sm text-slate-400">Automatically apply DENY policy for critical threats</p>
            </div>
            <ToggleSwitch checked={autoBlockHighThreats} onChange={setAutoBlockHighThreats} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">DRL Auto-decisions</p>
              <p className="text-sm text-slate-400">Allow AI to make autonomous policy decisions</p>
            </div>
            <ToggleSwitch checked={drlAutoDecisions} onChange={setDrlAutoDecisions} />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Confidence Threshold</label>
            <input
              type="range"
              min={0}
              max={100}
              value={confidenceThreshold}
              onChange={(e) => setConfidenceThreshold(Number(e.target.value))}
              className="w-full"
            />
            <p className="text-sm text-slate-400 mt-1">Current: {confidenceThreshold}%</p>
          </div>
        </div>
      </div>

      {/* Notification Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="font-semibold">Notifications</h3>
        </div>
        <div className="card-body space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Email Alerts</p>
              <p className="text-sm text-slate-400">Send email for critical threats</p>
            </div>
            <ToggleSwitch checked={emailAlerts} onChange={setEmailAlerts} />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Slack Integration</p>
              <p className="text-sm text-slate-400">Post alerts to Slack channel</p>
            </div>
            <ToggleSwitch checked={slackIntegration} onChange={setSlackIntegration} />
          </div>
        </div>
      </div>

      {saveMessage && (
        <p className={saveMessage.type === 'success' ? 'text-green-500 text-sm' : 'text-red-500 text-sm'}>
          {saveMessage.text}
        </p>
      )}
      <div className="flex justify-end">
        <button onClick={handleSave} disabled={saving} className="btn btn-primary">
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>
    </div>
  )
}

function ToggleSwitch({
  checked,
  onChange,
}: {
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="relative inline-flex items-center cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="sr-only peer"
      />
      <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600" />
    </label>
  )
}
