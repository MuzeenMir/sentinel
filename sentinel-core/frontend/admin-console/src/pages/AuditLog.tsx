import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ClipboardList, Filter } from 'lucide-react'
import { auditApi } from '../services/api'
import type { AuditEntry } from '../types'

export function AuditLog() {
  const [eventType, setEventType] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['audit-events', eventType, page],
    queryFn: () =>
      auditApi
        .getEvents({
          ...(eventType ? { event_type: eventType } : {}),
          page,
        })
        .then((r) => r.data),
  })

  const events: AuditEntry[] = data?.events ?? data ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ClipboardList className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Audit Log</h1>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Filter className="h-4 w-4 text-slate-400" />
        <select
          value={eventType}
          onChange={(e) => {
            setEventType(e.target.value)
            setPage(1)
          }}
          className="select-field"
        >
          <option value="">All actions</option>
          <option value="login">Login</option>
          <option value="logout">Logout</option>
          <option value="policy_create">Policy Create</option>
          <option value="policy_update">Policy Update</option>
          <option value="policy_delete">Policy Delete</option>
          <option value="scan">Scan</option>
          <option value="remediate">Remediate</option>
          <option value="config_update">Config Update</option>
        </select>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading audit log…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load audit log.</p>
        </div>
      ) : events.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No audit events found.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Timestamp</th>
                  <th className="table-header">User</th>
                  <th className="table-header">Action</th>
                  <th className="table-header">Resource Type</th>
                  <th className="table-header">Resource ID</th>
                  <th className="table-header">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {events.map((event) => (
                  <tr key={event.id} className="hover:bg-slate-800/30">
                    <td className="table-cell text-xs text-slate-400 whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="table-cell font-medium text-white">{event.user}</td>
                    <td className="table-cell">
                      <span className="badge bg-slate-600/30 text-slate-300 border border-slate-600/50">
                        {event.action}
                      </span>
                    </td>
                    <td className="table-cell text-slate-300">{event.resource_type}</td>
                    <td className="table-cell font-mono text-xs text-cyan-400">
                      {event.resource_id ?? '—'}
                    </td>
                    <td className="table-cell font-mono text-xs text-slate-400">
                      {event.ip_address ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="btn-secondary text-xs"
            >
              Previous
            </button>
            <span className="text-sm text-slate-400">Page {page}</span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={events.length === 0}
              className="btn-secondary text-xs"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
