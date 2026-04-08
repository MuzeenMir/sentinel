import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Play, ShieldCheck, Wrench } from 'lucide-react'
import { hardeningApi } from '../services/api'
import type { HardeningCheck, HardeningPosture } from '../types'

function statusBadge(status: string) {
  const map: Record<string, string> = {
    pass: 'bg-green-500/20 text-green-400 border-green-500/30',
    fail: 'bg-red-500/20 text-red-400 border-red-500/30',
    warning: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    info: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }
  return `badge border ${map[status] ?? ''}`
}

export function Hardening() {
  const queryClient = useQueryClient()

  const postureQuery = useQuery({
    queryKey: ['hardening-posture'],
    queryFn: () => hardeningApi.getPosture().then((r) => r.data),
  })

  const scanQuery = useQuery({
    queryKey: ['hardening-scan'],
    queryFn: () => hardeningApi.getScan().then((r) => r.data),
  })

  const scanMutation = useMutation({
    mutationFn: () => hardeningApi.triggerScan(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardening-scan'] })
      queryClient.invalidateQueries({ queryKey: ['hardening-posture'] })
    },
  })

  const remediateMutation = useMutation({
    mutationFn: (checkId: string) => hardeningApi.remediate(checkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardening-scan'] })
      queryClient.invalidateQueries({ queryKey: ['hardening-posture'] })
    },
  })

  const posture: HardeningPosture | null = postureQuery.data ?? null
  const checks: HardeningCheck[] = scanQuery.data?.checks ?? scanQuery.data ?? []

  const score = posture?.score ?? 0
  const circumference = 2 * Math.PI * 60
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Lock className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">System Hardening</h1>
        </div>
        <button
          onClick={() => scanMutation.mutate()}
          disabled={scanMutation.isPending}
          className="btn-primary gap-2"
        >
          <Play className="h-4 w-4" /> Scan
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-4">
        <div className="card p-6 flex flex-col items-center justify-center">
          <svg width="140" height="140" className="transform -rotate-90">
            <circle cx="70" cy="70" r="60" fill="none" stroke="#334155" strokeWidth="10" />
            <circle
              cx="70"
              cy="70"
              r="60"
              fill="none"
              stroke={score >= 80 ? '#10b981' : score >= 60 ? '#f59e0b' : '#ef4444'}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
            />
          </svg>
          <p className="mt-3 text-3xl font-bold text-white">{score}%</p>
          <p className="text-sm text-slate-400">Posture Score</p>
        </div>

        <div className="lg:col-span-3 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="card p-4">
            <ShieldCheck className="h-5 w-5 text-green-400 mb-2" />
            <p className="text-2xl font-bold text-white">{posture?.passed ?? 0}</p>
            <p className="text-sm text-slate-400">Passed</p>
          </div>
          <div className="card p-4">
            <ShieldCheck className="h-5 w-5 text-red-400 mb-2" />
            <p className="text-2xl font-bold text-white">{posture?.failed ?? 0}</p>
            <p className="text-sm text-slate-400">Failed</p>
          </div>
          <div className="card p-4">
            <ShieldCheck className="h-5 w-5 text-yellow-400 mb-2" />
            <p className="text-2xl font-bold text-white">{posture?.warnings ?? 0}</p>
            <p className="text-sm text-slate-400">Warnings</p>
          </div>
          <div className="card p-4">
            <ShieldCheck className="h-5 w-5 text-blue-400 mb-2" />
            <p className="text-2xl font-bold text-white">{posture?.total_checks ?? 0}</p>
            <p className="text-sm text-slate-400">Total Checks</p>
          </div>
        </div>
      </div>

      {scanQuery.isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading scan results…</p>
        </div>
      ) : scanQuery.isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load scan results.</p>
        </div>
      ) : checks.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No scan results. Run a scan to check system hardening.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-700">
            <h2 className="text-lg font-semibold text-white">CIS Benchmark Checks</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Check</th>
                  <th className="table-header">Category</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {checks.map((check) => (
                  <tr key={check.id} className="hover:bg-slate-800/30">
                    <td className="table-cell">
                      <p className="font-medium text-white">{check.title}</p>
                      <p className="text-xs text-slate-500 mt-0.5">{check.benchmark}</p>
                    </td>
                    <td className="table-cell text-slate-400">{check.category}</td>
                    <td className="table-cell">
                      <span className={statusBadge(check.status)}>{check.status}</span>
                    </td>
                    <td className="table-cell">
                      <span className={`badge-${check.severity}`}>{check.severity}</span>
                    </td>
                    <td className="table-cell">
                      {check.status === 'fail' && (
                        <button
                          onClick={() => remediateMutation.mutate(check.id)}
                          disabled={remediateMutation.isPending}
                          className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          <Wrench className="h-3 w-3" /> Remediate
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
