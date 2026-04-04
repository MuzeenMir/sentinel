import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Eye, Filter } from 'lucide-react'
import { hidsApi } from '../services/api'
import type { HIDSEvent } from '../types'

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
  }
  return map[severity] ?? 'badge-info'
}

export function HidsEvents() {
  const [eventType, setEventType] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['hids-events', eventType, page],
    queryFn: () =>
      hidsApi
        .getEvents({
          ...(eventType ? { event_type: eventType } : {}),
          page,
          per_page: 50,
        })
        .then((r) => r.data),
  })

  const events: HIDSEvent[] = data?.events ?? data ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Eye className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">HIDS Events</h1>
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
          <option value="">All event types</option>
          <option value="file_integrity">File Integrity</option>
          <option value="rootkit">Rootkit Detection</option>
          <option value="process">Process Anomaly</option>
          <option value="authentication">Authentication</option>
          <option value="network">Network</option>
        </select>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading HIDS events…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load HIDS events.</p>
        </div>
      ) : events.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No HIDS events found.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Event Type</th>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Source</th>
                  <th className="table-header">Description</th>
                  <th className="table-header">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {events.map((event) => (
                  <tr key={event.id} className="hover:bg-slate-800/30">
                    <td className="table-cell">
                      <span className="badge bg-slate-600/30 text-slate-300 border border-slate-600/50">
                        {event.event_type}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span className={severityBadge(event.severity)}>{event.severity}</span>
                    </td>
                    <td className="table-cell font-mono text-xs">{event.source}</td>
                    <td className="table-cell max-w-xs truncate">{event.description}</td>
                    <td className="table-cell text-slate-400 text-xs whitespace-nowrap">
                      {new Date(event.timestamp).toLocaleString()}
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
              disabled={events.length < 50}
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
