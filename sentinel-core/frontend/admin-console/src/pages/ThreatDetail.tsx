import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Shield, AlertTriangle } from 'lucide-react'
import { threatApi } from '../services/api'
import type { Threat } from '../types'

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
  }
  return map[severity] ?? 'badge-info'
}

export function ThreatDetail() {
  const { id } = useParams<{ id: string }>()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['threat', id],
    queryFn: () => threatApi.getThreat(id!).then((r) => r.data),
    enabled: !!id,
  })

  const threat: Threat | undefined = data?.threat ?? data

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-slate-400">Loading threat details…</p>
      </div>
    )
  }

  if (isError || !threat) {
    return (
      <div className="space-y-4">
        <Link
          to="/threats"
          className="inline-flex items-center gap-2 text-sm text-cyan-400 hover:text-cyan-300"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Threats
        </Link>
        <div className="card p-12 text-center">
          <AlertTriangle className="mx-auto h-8 w-8 text-red-400 mb-3" />
          <p className="text-red-400">Failed to load threat details.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link to="/threats" className="text-slate-400 hover:text-white">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Threat: {threat.id}</h1>
        </div>
        <span className={severityBadge(threat.severity)}>{threat.severity}</span>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-6">
          <div className="card p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Overview</h2>
            <dl className="grid grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-slate-400">Type</dt>
                <dd className="mt-1 text-sm font-medium text-white">{threat.type}</dd>
              </div>
              <div>
                <dt className="text-sm text-slate-400">Status</dt>
                <dd className="mt-1 text-sm font-medium text-white">{threat.status}</dd>
              </div>
              <div>
                <dt className="text-sm text-slate-400">Source IP</dt>
                <dd className="mt-1 text-sm font-mono text-white">{threat.source_ip ?? '—'}</dd>
              </div>
              <div>
                <dt className="text-sm text-slate-400">Destination IP</dt>
                <dd className="mt-1 text-sm font-mono text-white">
                  {threat.destination_ip ?? '—'}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-400">Confidence</dt>
                <dd className="mt-1 text-sm font-medium text-white">
                  {threat.confidence != null ? `${threat.confidence}%` : '—'}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-400">Detected</dt>
                <dd className="mt-1 text-sm text-white">
                  {new Date(threat.timestamp).toLocaleString()}
                </dd>
              </div>
            </dl>
          </div>

          {threat.description && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-3">Description</h2>
              <p className="text-sm text-slate-300 leading-relaxed">{threat.description}</p>
            </div>
          )}

          {threat.explanation && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-3">AI Explanation</h2>
              <p className="text-sm text-slate-300 leading-relaxed">{threat.explanation}</p>
            </div>
          )}
        </div>

        <div className="space-y-6">
          {threat.model_verdicts && threat.model_verdicts.length > 0 && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Model Verdicts</h2>
              <div className="space-y-3">
                {threat.model_verdicts.map((v, i) => (
                  <div key={i} className="rounded-lg border border-slate-700 p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-white">{v.model}</span>
                      <span className="text-xs text-cyan-400">{v.confidence}%</span>
                    </div>
                    <p className="text-xs text-slate-400">{v.verdict}</p>
                    {v.explanation && (
                      <p className="mt-1 text-xs text-slate-500">{v.explanation}</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {threat.details && Object.keys(threat.details).length > 0 && (
            <div className="card p-6">
              <h2 className="text-lg font-semibold text-white mb-3">Raw Details</h2>
              <pre className="text-xs text-slate-400 overflow-auto max-h-64 rounded-lg bg-slate-900 p-3">
                {JSON.stringify(threat.details, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
