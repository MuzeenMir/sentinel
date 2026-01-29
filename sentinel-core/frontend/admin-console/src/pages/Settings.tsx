import { appConfig } from '../config/runtime'

export function Settings() {
  const apiLabel = appConfig.apiBaseUrl || 'same-origin'

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
            <input type="text" defaultValue="SENTINEL Security" className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Default Timezone</label>
            <select className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
              <option>UTC</option>
              <option>America/New_York</option>
              <option>Europe/London</option>
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
            <ToggleSwitch defaultChecked />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">DRL Auto-decisions</p>
              <p className="text-sm text-slate-400">Allow AI to make autonomous policy decisions</p>
            </div>
            <ToggleSwitch defaultChecked />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Confidence Threshold</label>
            <input type="range" min="0" max="100" defaultValue="85" className="w-full" />
            <p className="text-sm text-slate-400 mt-1">Current: 85%</p>
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
            <ToggleSwitch defaultChecked />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">Slack Integration</p>
              <p className="text-sm text-slate-400">Post alerts to Slack channel</p>
            </div>
            <ToggleSwitch />
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button className="btn btn-primary">Save Settings</button>
      </div>
    </div>
  )
}

function ToggleSwitch({ defaultChecked = false }: { defaultChecked?: boolean }) {
  return (
    <label className="relative inline-flex items-center cursor-pointer">
      <input type="checkbox" defaultChecked={defaultChecked} className="sr-only peer" />
      <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
    </label>
  )
}
