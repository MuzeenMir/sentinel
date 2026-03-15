import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { hidsApi } from '../services/api'

interface HidsEvent {
  id: string
  event_type: string
  pid?: number
  uid?: number
  comm?: string
  filename?: string
  path?: string
  src_ip?: string
  dst_ip?: string
  dst_port?: number
  severity?: string
  timestamp_ns?: number
  timestamp?: string
}

const EVENT_TYPE_LABELS: Record<string, string> = {
  process_exec: 'Process Exec',
  file_access: 'File Access',
  net_connect: 'Net Connect',
  priv_escalation: 'Priv Escalation',
  module_load: 'Module Load',
  fim_alert: 'FIM Alert',
}

const EVENT_SEVERITY: Record<string, string> = {
  priv_escalation: 'status-critical',
  module_load: 'status-high',
  fim_alert: 'status-high',
  net_connect: 'status-medium',
  file_access: 'status-low',
  process_exec: 'status-low',
}

const PAGE_SIZE = 50

export function HidsEvents() {
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all')
  const [page, setPage] = useState(1)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['hids-events', eventTypeFilter, page],
    queryFn: async () => {
      const params: Record<string, string | number> = { page, per_page: PAGE_SIZE }
      if (eventTypeFilter !== 'all') params.event_type = eventTypeFilter
      const res = await hidsApi.getEvents(params)
      return res.data
    },
  })

  const { data: statusData } = useQuery({
    queryKey: ['hids-status'],
    queryFn: async () => {
      const res = await hidsApi.getStatus()
      return res.data
    },
  })

  const events: HidsEvent[] = (data as { events?: HidsEvent[] })?.events ?? []
  const total: number = (data as { total?: number })?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const status = statusData as { ebpf_enabled?: boolean; fim_enabled?: boolean; monitoring_paths?: string[] } | undefined

  const formatTimestamp = (event: HidsEvent) => {
    if (event.timestamp) return new Date(event.timestamp).toLocaleString()
    if (event.timestamp_ns) return new Date(event.timestamp_ns / 1e6).toLocaleString()
    return '—'
  }

  const formatDetails = (event: HidsEvent) => {
    if (event.event_type === 'process_exec') return `${event.comm ?? ''} (pid ${event.pid ?? '?'})`
    if (event.event_type === 'file_access') return event.filename ?? event.path ?? '—'
    if (event.event_type === 'net_connect') return `${event.src_ip ?? '?'} → ${event.dst_ip ?? '?'}:${event.dst_port ?? '?'}`
    if (event.event_type === 'priv_escalation') return `uid ${event.uid ?? '?'} → root (${event.comm ?? 'unknown'})`
    if (event.event_type === 'module_load') return event.filename ?? '—'
    if (event.event_type === 'fim_alert') return event.path ?? '—'
    return '—'
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">HIDS Event Log</h1>
        <p className="text-sm text-slate-400 mt-1">
          eBPF-powered host intrusion detection events
        </p>
      </div>

      {/* Status row */}
      {status && (
        <div className="flex gap-4 flex-wrap">
          <div className={clsx('flex items-center gap-2 text-sm', status.ebpf_enabled ? 'text-green-400' : 'text-yellow-400')}>
            <span className={clsx('w-2 h-2 rounded-full', status.ebpf_enabled ? 'bg-green-400' : 'bg-yellow-400')} />
            eBPF: {status.ebpf_enabled ? 'Active' : 'Inactive (FIM-only mode)'}
          </div>
          <div className={clsx('flex items-center gap-2 text-sm', status.fim_enabled ? 'text-green-400' : 'text-slate-400')}>
            <span className={clsx('w-2 h-2 rounded-full', status.fim_enabled ? 'bg-green-400' : 'bg-slate-400')} />
            FIM: {status.fim_enabled ? 'Active' : 'Inactive'}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap items-end">
        <div>
          <label className="text-xs text-slate-400 block mb-1">Event Type</label>
          <select
            value={eventTypeFilter}
            onChange={(e) => { setEventTypeFilter(e.target.value); setPage(1) }}
            className="input text-sm"
          >
            <option value="all">All types</option>
            {Object.entries(EVENT_TYPE_LABELS).map(([key, label]) => (
              <option key={key} value={key}>{label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Events table */}
      <div className="card">
        {isLoading && (
          <div className="p-8 text-center text-slate-400 text-sm">Loading events…</div>
        )}
        {isError && (
          <div className="p-8 text-center text-red-400 text-sm">
            Failed to load HIDS events. Ensure the hids-agent is running.
          </div>
        )}
        {!isLoading && !isError && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">Time</th>
                  <th className="px-6 py-3 text-left font-medium">Type</th>
                  <th className="px-6 py-3 text-left font-medium">Severity</th>
                  <th className="px-6 py-3 text-left font-medium">PID</th>
                  <th className="px-6 py-3 text-left font-medium">UID</th>
                  <th className="px-6 py-3 text-left font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, idx) => (
                  <tr key={event.id ?? idx} className={clsx('border-b border-slate-800/50 hover:bg-slate-900/60', {
                    'bg-red-900/10': event.event_type === 'priv_escalation' || event.event_type === 'module_load',
                    'bg-yellow-900/10': event.event_type === 'fim_alert',
                  })}>
                    <td className="px-6 py-3 text-xs text-slate-400 whitespace-nowrap">
                      {formatTimestamp(event)}
                    </td>
                    <td className="px-6 py-3">
                      <span className={clsx('status-badge', EVENT_SEVERITY[event.event_type] ?? 'status-low')}>
                        {EVENT_TYPE_LABELS[event.event_type] ?? event.event_type}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-xs text-slate-400">
                      {event.severity ?? '—'}
                    </td>
                    <td className="px-6 py-3 text-xs font-mono">{event.pid ?? '—'}</td>
                    <td className="px-6 py-3 text-xs font-mono">{event.uid ?? '—'}</td>
                    <td className="px-6 py-3 text-xs font-mono text-slate-300 max-w-xs truncate">
                      {formatDetails(event)}
                    </td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-sm text-slate-400">
                      No events recorded yet.
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
            <p className="text-xs text-slate-400">Page {page} of {totalPages} ({total} events)</p>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500"
              >Previous</button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 text-xs rounded border border-slate-700 disabled:opacity-40 hover:border-slate-500"
              >Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
