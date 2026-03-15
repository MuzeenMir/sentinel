import { useQuery } from '@tanstack/react-query'
import { useParams, useNavigate } from 'react-router-dom'
import { threatApi } from '../services/api'

export function ThreatDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['threat', id],
    queryFn: async () => {
      if (!id) throw new Error('Missing threat id')
      const res = await threatApi.getThreat(id)
      return res.data
    },
    enabled: !!id,
  })

  const threat = data?.threat || data

  return (
    <div className="space-y-6">
      <button
        onClick={() => navigate(-1)}
        className="text-sm text-slate-400 hover:text-slate-200"
      >
        ← Back to threats
      </button>

      <div className="card p-6">
        {isLoading && <p className="text-sm text-gray-400">Loading threat details...</p>}
        {isError && (
          <p className="text-sm text-red-400">
            Failed to load threat details. This may be due to missing backend support for
            `/api/v1/threats/{id}`.
          </p>
        )}
        {!isLoading && !isError && threat && (
          <>
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-4">
              <div>
                <h2 className="text-xl font-semibold">Threat {threat.id || id}</h2>
                <p className="text-sm text-slate-400">{threat.type || 'network_anomaly'}</p>
              </div>
              <div className="flex gap-2 items-center">
                {(() => {
                  const severity = String(threat.severity || 'medium').toLowerCase()
                  return (
                    <span className={`status-badge status-${severity}`}>
                      {severity}
                    </span>
                  )
                })()}
                {threat.status && (
                  <span className="px-2 py-1 rounded text-xs font-medium bg-blue-900/50 text-blue-300 border border-blue-800/80 capitalize">
                    {String(threat.status).replace('_', ' ')}
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="text-sm font-semibold text-slate-300 mb-2">Context</h3>
                <div className="text-sm text-slate-300 space-y-1">
                  <p>
                    <span className="text-slate-500">Source:</span>{' '}
                    <span className="font-mono">{threat.source_ip || threat.source}</span>
                  </p>
                  <p>
                    <span className="text-slate-500">Destination:</span>{' '}
                    <span className="font-mono">
                      {threat.dest_ip || threat.destination || threat.target}
                    </span>
                  </p>
                  <p>
                    <span className="text-slate-500">Time:</span>{' '}
                    {(threat.timestamp || threat.time)
                      ? new Date(threat.timestamp || threat.time).toLocaleString()
                      : '—'}
                  </p>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-semibold text-slate-300 mb-2">Details</h3>
                <pre className="text-xs bg-slate-950/80 border border-slate-800/80 rounded-lg p-3 overflow-auto max-h-64">
                  {JSON.stringify(threat.details || threat, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

