import { useState } from 'react'

const mockPolicies = [
  { id: 'P001', name: 'Block SSH Brute Force', action: 'DENY', source: '0.0.0.0/0', destination: '*:22', status: 'active', matches: 1247 },
  { id: 'P002', name: 'Rate Limit API Requests', action: 'RATE_LIMIT', source: '0.0.0.0/0', destination: '*:443', status: 'active', matches: 45230 },
  { id: 'P003', name: 'Block Known Malware IPs', action: 'DENY', source: 'threat_intel_list', destination: '*', status: 'active', matches: 892 },
  { id: 'P004', name: 'Allow Internal Traffic', action: 'ALLOW', source: '10.0.0.0/8', destination: '10.0.0.0/8', status: 'active', matches: 125000 },
  { id: 'P005', name: 'Quarantine Infected Hosts', action: 'QUARANTINE', source: 'dynamic', destination: '*', status: 'active', matches: 15 },
]

export function Policies() {
  const [, setShowCreateModal] = useState(false)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h3 className="text-lg font-semibold">Active Policies</h3>
          <p className="text-sm text-slate-400">Manage firewall and security policies</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn btn-secondary">Import Pack</button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-primary"
          >
            + Create Policy
          </button>
        </div>
      </div>

      {/* Policy Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-sm text-slate-400">Total Policies</p>
          <p className="text-2xl font-bold">{mockPolicies.length}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">DENY Rules</p>
          <p className="text-2xl font-bold text-red-400">{mockPolicies.filter(p => p.action === 'DENY').length}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">ALLOW Rules</p>
          <p className="text-2xl font-bold text-emerald-400">{mockPolicies.filter(p => p.action === 'ALLOW').length}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">Total Matches</p>
          <p className="text-2xl font-bold">{mockPolicies.reduce((a, p) => a + p.matches, 0).toLocaleString()}</p>
        </div>
      </div>

      {/* Policies Table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                <th className="px-6 py-3 text-left font-medium">ID</th>
                <th className="px-6 py-3 text-left font-medium">Name</th>
                <th className="px-6 py-3 text-left font-medium">Action</th>
                <th className="px-6 py-3 text-left font-medium">Source</th>
                <th className="px-6 py-3 text-left font-medium">Destination</th>
                <th className="px-6 py-3 text-left font-medium">Matches</th>
                <th className="px-6 py-3 text-left font-medium">Status</th>
                <th className="px-6 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockPolicies.map((policy) => (
                <tr key={policy.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                  <td className="px-6 py-4 text-sm font-mono">{policy.id}</td>
                  <td className="px-6 py-4 text-sm font-medium">{policy.name}</td>
                  <td className="px-6 py-4">
                    <ActionBadge action={policy.action} />
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-slate-300">{policy.source}</td>
                  <td className="px-6 py-4 text-sm font-mono text-slate-300">{policy.destination}</td>
                  <td className="px-6 py-4 text-sm">{policy.matches.toLocaleString()}</td>
                  <td className="px-6 py-4">
                    <span className="status-badge status-compliant">{policy.status}</span>
                  </td>
                  <td className="px-6 py-4 space-x-2">
                    <button className="text-blue-400 hover:text-blue-300 text-sm">Edit</button>
                    <button className="text-red-400 hover:text-red-300 text-sm">Disable</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function ActionBadge({ action }: { action: string }) {
  const colors: Record<string, string> = {
    DENY: 'bg-red-900/50 text-red-400 border-red-800',
    ALLOW: 'bg-green-900/50 text-green-400 border-green-800',
    RATE_LIMIT: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
    QUARANTINE: 'bg-purple-900/50 text-purple-400 border-purple-800',
    MONITOR: 'bg-blue-900/50 text-blue-400 border-blue-800',
  }
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium border ${colors[action] || colors.MONITOR}`}>
      {action}
    </span>
  )
}
