import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { threatApi } from '../services/api'

export function Threats() {
  const [filter, setFilter] = useState<string>('all')
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['threats'],
    queryFn: async () => {
      const res = await threatApi.getThreats()
      return res.data
    },
  })

  const threats = (data?.threats as any[]) || []

  const filteredThreats = filter === 'all'
    ? threats
    : threats.filter(t => (t.severity || '').toLowerCase() === filter)

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <span className="text-sm text-gray-400">Filter by severity:</span>
        {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded text-sm capitalize ${
              filter === f ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Threats Table */}
      <div className="card">
        <div className="overflow-x-auto">
          {isLoading && (
            <p className="px-6 py-4 text-sm text-gray-400">Loading threats...</p>
          )}
          {isError && (
            <p className="px-6 py-4 text-sm text-red-400">
              Failed to load threats from backend. Ensure `/api/v1/threats` is reachable from the API gateway.
            </p>
          )}
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.map((threat) => (
                <tr
                  key={threat.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                  onClick={() => navigate(`/threats/${encodeURIComponent(threat.id)}`)}
                >
                  <td className="px-6 py-4 text-sm font-mono">{threat.id}</td>
                  <td className="px-6 py-4 text-sm">{threat.type || 'network_anomaly'}</td>
                  <td className="px-6 py-4">
                    <span className={`status-badge status-${(threat.severity || 'medium').toLowerCase()}`}>
                      {threat.severity || 'medium'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-300">
                    {threat.source_ip || threat.source}
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-300">
                    {threat.dest_ip || threat.destination || threat.target}
                  </td>
                  <td className="px-6 py-4 text-sm capitalize text-green-400">
                    {String(threat.status || 'new').replace('_', ' ')}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-400">
                    {new Date(threat.timestamp || threat.time || Date.now()).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 space-x-2 text-right pr-8">
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        navigate(`/threats/${encodeURIComponent(threat.id)}`)
                      }}
                      className="text-blue-400 hover:text-blue-300 text-sm"
                    >
                      Investigate
                    </button>
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
