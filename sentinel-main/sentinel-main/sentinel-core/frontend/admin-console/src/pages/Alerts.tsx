import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { alertApi } from '../services/api'
import type { Alert, AlertStatus, Severity } from '../types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'status-critical',
  high: 'status-high',
  medium: 'status-medium',
  low: 'status-low',
}

const STATUS_LABELS: Record<AlertStatus, string> = {
  new: 'New',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  ignored: 'Ignored',
}

const PAGE_SIZE = 20

export function Alerts() {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | 'all'>('all')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [page, setPage] = useState(1)
  const queryClient = useQueryClient()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['alerts', statusFilter, severityFilter, page],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, per_page: PAGE_SIZE }
      if (statusFilter !== 'all') params.status = statusFilter
      if (severityFilter !== 'all') params.severity = severityFilter
      const res = await alertApi.getAlerts(params)
      return res.data
    },
  })

  const { data: statsData } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: async () => {
      const res = await alertApi.getStats()
      return res.data
    },
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['alert-stats'] })
  }

  const ackMut = useMutation({
    mutationFn: (id: string) => alertApi.acknowledge(id),
    onSuccess: invalidate,
  })
  const resMut = useMutation({
    mutationFn: (id: string) => alertApi.resolve(id),
    onSuccess: invalidate,
  })
  const ignMut = useMutation({
    mutationFn: (id: string) => alertApi.ignore(id),
    onSuccess: invalidate,
  })

  const alerts: Alert[] = (data as { alerts?: Alert[] })?.alerts ?? []
  const total: number = (data as { total?: number })?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const stats = statsData as Record<string, number> | undefined

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Alerts</h1>
        <p className="text-sm text-slate-400 mt-1">
          Manage security alerts from all detection sources
        </p>
      </div>

      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {(['new', 'acknowledged', 'resolved', 'ignored'] as AlertStatus[]).map((s) => (
            <div key={s} className="card p-4">
              <p className="text-xs text-slate-400 uppercase tracking-wide">{STATUS_LABELS[s]}</p>
              <p className="text-2xl font-bold mt-1">{stats[s] ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div>
          <label className="text-xs text-slate-400 block mb-1">Status</label>
          <select
            value={statusFilter}
            onChange={(e) => { setStatusFilter(e.target.value as AlertStatus | 'all'); setPage(1) }}
            className="input text-sm"
          >
            <option value="all">All statuses</option>
            {(['new', 'acknowledged', 'resolved', 'ignored'] as AlertStatus[]).map((s) => (
              <option key={s} value={s}>{STATUS_LABELS[s]}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-slate-400 block mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value as Severity | 'all'); setPage(1) }}
            className="input text-sm"
          >
            <option value="all">All severities</option>
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Alerts table */}
      <div className="card">
        {isLoading && (
          <div className="p-8 text-center text-slate-400 text-sm">Loading alerts…</div>
        )}
        {isError && (
          <div className="p-8 text-center text-red-400 text-sm">
            Failed to load alerts. Check that the alert-service is running.
          </div>
        )}
        {!isLoading && !isError && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">Severity</th>
                  <th className="px-6 py-3 text-left font-medium">Type</th>
                  <th className="px-6 py-3 text-left font-medium">Source</th>
                  <th className="px-6 py-3 text-left font-medium">Description</th>
                  <th className="px-6 py-3 text-left font-medium">Time</th>
                  <th className="px-6 py-3 text-left font-medium">Status</th>
                  <th className="px-6 py-3 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                    <td className="px-6 py-4">
                      <span className={clsx('status-badge', SEVERITY_COLORS[alert.severity] ?? 'status-medium')}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm">{alert.type}</td>
                    <td className="px-6 py-4 text-sm font-mono text-slate-300">{alert.source}</td>
                    <td className="px-6 py-4 text-sm text-slate-400 max-w-xs truncate">
                      {alert.description}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 text-xs">
                      <span className={clsx('px-2 py-1 rounded-full text-xs font-medium', {
                        'bg-blue-500/20 text-blue-300': alert.status === 'new',
                        'bg-yellow-500/20 text-yellow-300': alert.status === 'acknowledged',
                        'bg-green-500/20 text-green-300': alert.status === 'resolved',
                        'bg-slate-500/20 text-slate-400': alert.status === 'ignored',
                      })}>
                        {STATUS_LABELS[alert.status]}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2 text-xs">
                        {alert.status === 'new' && (
                          <button
                            onClick={() => ackMut.mutate(alert.id)}
                            className="text-yellow-400 hover:text-yellow-300"
                          >
                            Acknowledge
                          </button>
                        )}
                        {alert.status !== 'resolved' && alert.status !== 'ignored' && (
                          <button
                            onClick={() => resMut.mutate(alert.id)}
                            className="text-green-400 hover:text-green-300"
                          >
                            Resolve
                          </button>
                        )}
                        {alert.status === 'new' && (
                          <button
                            onClick={() => ignMut.mutate(alert.id)}
                            className="text-slate-400 hover:text-slate-300"
                          >
                            Ignore
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-6 py-8 text-center text-sm text-slate-400">
                      No alerts match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800/80">
            <p className="text-xs text-slate-400">
              Showing page {page} of {totalPages} ({total} total)
            </p>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500"
              >
                Previous
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
