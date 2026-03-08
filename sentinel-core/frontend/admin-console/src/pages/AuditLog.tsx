import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { auditApi } from '../services/api'

interface AuditEvent {
  id: string
  event_type: string
  user?: string
  resource?: string
  action?: string
  result: 'success' | 'failure'
  ip_address?: string
  timestamp: string
  details?: Record<string, unknown>
}

const EVENT_TYPES = [
  'login',
  'login_failure',
  'logout',
  'policy_change',
  'alert_ack',
  'user_update',
  'hardening_scan',
  'remediation',
]

const PAGE_SIZE = 50

export function AuditLog() {
  const [eventTypeFilter, setEventTypeFilter] = useState('all')
  const [page, setPage] = useState(1)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['audit-events', eventTypeFilter, page],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, per_page: PAGE_SIZE }
      if (eventTypeFilter !== 'all') params.event_type = eventTypeFilter
      const res = await auditApi.getEvents(params)
      return res.data
    },
  })

  const events: AuditEvent[] = (data as { events?: AuditEvent[] })?.events ?? []
  const total: number = (data as { total?: number })?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <p className="text-sm text-slate-400 mt-1">
          Read-only record of all security-sensitive actions
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-end">
        <div>
          <label className="text-xs text-slate-400 block mb-1">Event Type</label>
          <select
            value={eventTypeFilter}
            onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1) }}
            className="input text-sm"
          >
            <option value="all">All events</option>
            {EVENT_TYPES.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="card">
        {isLoading && (
          <div className="p-8 text-center text-slate-400 text-sm">Loading audit log…</div>
        )}
        {isError && (
          <div className="p-8 text-center text-red-400 text-sm">
            Failed to load audit log. Ensure the auth-service is running.
          </div>
        )}
        {!isLoading && !isError && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">Time</th>
                  <th className="px-6 py-3 text-left font-medium">Event</th>
                  <th className="px-6 py-3 text-left font-medium">User</th>
                  <th className="px-6 py-3 text-left font-medium">Resource</th>
                  <th className="px-6 py-3 text-left font-medium">IP</th>
                  <th className="px-6 py-3 text-left font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, idx) => (
                  <tr
                    key={event.id ?? idx}
                    className={event.result === 'failure' ? 'border-b border-slate-800/50 bg-red-900/10' : 'border-b border-slate-800/50 hover:bg-slate-900/60'}
                  >
                    <td className="px-6 py-3 text-xs text-slate-400 whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-300">
                      {event.event_type}
                    </td>
                    <td className="px-6 py-3 text-sm">{event.user ?? '—'}</td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-400 max-w-xs truncate">
                      {event.resource ?? event.action ?? '—'}
                    </td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-400">
                      {event.ip_address ?? '—'}
                    </td>
                    <td className="px-6 py-3">
                      <span className={event.result === 'success' ? 'text-xs text-green-400' : 'text-xs text-red-400'}>
                        {event.result}
                      </span>
                    </td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-sm text-slate-400">
                      No audit events found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-6 py-4 border-t border-slate-800/80">
            <p className="text-xs text-slate-400">Page {page} of {totalPages} ({total} events)</p>
            <div className="flex gap-2">
              <button disabled={page <= 1} onClick={() => setPage((p) => p - 1)} className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500">Previous</button>
              <button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)} className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
