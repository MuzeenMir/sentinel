import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { threatApi } from '../services/api'
import { appConfig } from '../config/runtime'

export function Threats() {
  const [filter, setFilter] = useState<string>('all')
  const [query, setQuery] = useState<string>('')
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['threats'],
    queryFn: async () => {
      const res = await threatApi.getThreats()
      return res.data
    },
  })

  const threats = (data?.threats as any[]) || []
  const normalizedQuery = query.trim().toLowerCase()

  const filteredThreats = threats.filter((threat) => {
    const severity = String(threat.severity || '').toLowerCase()
    const matchesSeverity = filter === 'all' || severity === filter

    if (!normalizedQuery) {
      return matchesSeverity
    }

    const searchable = [
      threat.id,
      threat.type,
      threat.source_ip,
      threat.source,
      threat.dest_ip,
      threat.destination,
      threat.target,
      threat.status,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()

    return matchesSeverity && searchable.includes(normalizedQuery)
  })

  const severityCounts = threats.reduce<Record<string, number>>((acc, threat) => {
    const key = String(threat.severity || 'unknown').toLowerCase()
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h3 className="text-lg font-semibold">Threats</h3>
          <p className="text-sm text-slate-400">Monitor detections from all data sources.</p>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative">
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by IP, type, or ID"
              className="w-full sm:w-72 rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
            />
          </div>
          <button className="btn btn-secondary">Export CSV</button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-xs uppercase tracking-[0.25em] text-slate-500">Total</p>
          <p className="text-2xl font-semibold mt-2">{threats.length}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs uppercase tracking-[0.25em] text-slate-500">Critical</p>
          <p className="text-2xl font-semibold mt-2 text-red-400">{severityCounts.critical || 0}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs uppercase tracking-[0.25em] text-slate-500">High</p>
          <p className="text-2xl font-semibold mt-2 text-orange-300">{severityCounts.high || 0}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs uppercase tracking-[0.25em] text-slate-500">Medium/Low</p>
          <p className="text-2xl font-semibold mt-2 text-emerald-300">
            {(severityCounts.medium || 0) + (severityCounts.low || 0)}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm text-slate-400">Filter by severity:</span>
        {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={clsx(
              'px-3 py-1 rounded-lg text-sm capitalize border transition-colors',
              filter === f
                ? 'bg-blue-600/20 text-blue-200 border-blue-500/40'
                : 'bg-slate-900/60 text-slate-300 border-slate-800/80 hover:bg-slate-800/70'
            )}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Threats Table */}
      <div className="card">
        <div className="overflow-x-auto">
          {isLoading && (
            <p className="px-6 py-4 text-sm text-slate-400">Loading threats...</p>
          )}
          {isError && (
            <div className="px-6 py-4 text-sm text-red-300">
              <p>Failed to load threats from the API gateway.</p>
              <p className="text-xs text-slate-500 mt-1">
                Check connectivity to <span className="font-mono">{appConfig.apiBaseUrl || 'same-origin'}</span>
                and ensure <span className="font-mono">/api/v1/threats</span> is reachable.
              </p>
            </div>
          )}
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                <th className="px-6 py-3 text-left font-medium">ID</th>
                <th className="px-6 py-3 text-left font-medium">Type</th>
                <th className="px-6 py-3 text-left font-medium">Severity</th>
                <th className="px-6 py-3 text-left font-medium">Source</th>
                <th className="px-6 py-3 text-left font-medium">Target</th>
                <th className="px-6 py-3 text-left font-medium">Status</th>
                <th className="px-6 py-3 text-left font-medium">Time</th>
                <th className="px-6 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.map((threat) => {
                const severity = String(threat.severity || 'medium').toLowerCase()
                return (
                  <tr
                    key={threat.id}
                    className="border-b border-slate-800/50 hover:bg-slate-900/60 cursor-pointer"
                    onClick={() => navigate(`/threats/${encodeURIComponent(threat.id)}`)}
                  >
                    <td className="px-6 py-4 text-sm font-mono">{threat.id}</td>
                    <td className="px-6 py-4 text-sm">{threat.type || 'network_anomaly'}</td>
                    <td className="px-6 py-4">
                      <span className={`status-badge status-${severity}`}>
                        {severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm font-mono text-slate-300">
                      {threat.source_ip || threat.source}
                    </td>
                    <td className="px-6 py-4 text-sm font-mono text-slate-300">
                      {threat.dest_ip || threat.destination || threat.target}
                    </td>
                    <td className="px-6 py-4 text-sm capitalize text-emerald-300">
                      {String(threat.status || 'new').replace('_', ' ')}
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400">
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
                )
              })}
              {!isLoading && filteredThreats.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-6 py-6 text-center text-sm text-slate-400">
                    No threats match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
