import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { hardeningApi } from '../services/api'

interface CISCheck {
  id: string
  name: string
  category: string
  status: 'pass' | 'fail' | 'warn' | 'error'
  severity: 'critical' | 'high' | 'medium' | 'low'
  current_value?: string
  expected_value?: string
  remediation?: string
  auto_remediable?: boolean
}

interface PostureData {
  score: number
  total_checks: number
  passed: number
  failed: number
  warnings: number
  last_scan?: string
}

export function Hardening() {
  const [remediatingId, setRemediatingId] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data: postureData, isLoading: postureLoading } = useQuery({
    queryKey: ['hardening-posture'],
    queryFn: async () => {
      const res = await hardeningApi.getPosture()
      return res.data as PostureData
    },
  })

  const {
    data: scanData,
    isLoading: scanLoading,
    isError,
  } = useQuery({
    queryKey: ['hardening-scan'],
    queryFn: async () => {
      const res = await hardeningApi.getScan()
      return res.data
    },
  })

  const scanMut = useMutation({
    mutationFn: () => hardeningApi.triggerScan(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardening-scan'] })
      queryClient.invalidateQueries({ queryKey: ['hardening-posture'] })
    },
  })

  const remediateMut = useMutation({
    mutationFn: (checkId: string) => hardeningApi.remediate(checkId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hardening-scan'] })
      queryClient.invalidateQueries({ queryKey: ['hardening-posture'] })
      setRemediatingId(null)
    },
    onError: () => setRemediatingId(null),
  })

  const checks: CISCheck[] = (scanData as { checks?: CISCheck[] })?.checks ?? []
  const failedChecks = checks.filter((c) => c.status === 'fail')
  const passedChecks = checks.filter((c) => c.status === 'pass')

  const posture = postureData
  const score = posture?.score ?? (checks.length > 0 ? Math.round((passedChecks.length / checks.length) * 100) : 0)

  const scoreColor = score >= 80 ? 'text-green-400' : score >= 60 ? 'text-yellow-400' : 'text-red-400'

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">System Hardening</h1>
          <p className="text-sm text-slate-400 mt-1">
            CIS Benchmark status and automated remediation
          </p>
        </div>
        <button
          onClick={() => scanMut.mutate()}
          disabled={scanMut.isPending}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm font-medium"
        >
          {scanMut.isPending ? 'Scanning…' : 'Run Scan'}
        </button>
      </div>

      {/* Posture score */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4 md:col-span-1">
          <p className="text-xs text-slate-400 uppercase tracking-wide">Posture Score</p>
          <p className={clsx('text-4xl font-bold mt-1', scoreColor)}>{score}%</p>
        </div>
        <div className="card p-4">
          <p className="text-xs text-slate-400 uppercase tracking-wide">Total Checks</p>
          <p className="text-2xl font-bold mt-1">{posture?.total_checks ?? checks.length}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs text-slate-400 uppercase tracking-wide">Passed</p>
          <p className="text-2xl font-bold text-green-400 mt-1">{posture?.passed ?? passedChecks.length}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs text-slate-400 uppercase tracking-wide">Failed</p>
          <p className="text-2xl font-bold text-red-400 mt-1">{posture?.failed ?? failedChecks.length}</p>
        </div>
      </div>

      {posture?.last_scan && (
        <p className="text-xs text-slate-500">Last scan: {new Date(posture.last_scan).toLocaleString()}</p>
      )}

      {/* Checks table */}
      <div className="card">
        <div className="card-header">
          <h3 className="font-semibold">CIS Benchmark Checks</h3>
          <p className="text-xs text-slate-500 mt-1">
            {failedChecks.length} check{failedChecks.length !== 1 ? 's' : ''} require attention
          </p>
        </div>

        {(scanLoading || postureLoading) && (
          <div className="p-8 text-center text-slate-400 text-sm">Loading scan results…</div>
        )}
        {isError && (
          <div className="p-8 text-center text-red-400 text-sm">
            Failed to load scan results. Ensure hardening-service is running.
          </div>
        )}
        {!scanLoading && !isError && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">Check</th>
                  <th className="px-6 py-3 text-left font-medium">Category</th>
                  <th className="px-6 py-3 text-left font-medium">Severity</th>
                  <th className="px-6 py-3 text-left font-medium">Status</th>
                  <th className="px-6 py-3 text-left font-medium">Current Value</th>
                  <th className="px-6 py-3 text-left font-medium">Expected</th>
                  <th className="px-6 py-3 text-left font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((check) => (
                  <tr key={check.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                    <td className="px-6 py-4 text-sm font-medium">{check.name}</td>
                    <td className="px-6 py-4 text-xs text-slate-400">{check.category}</td>
                    <td className="px-6 py-4">
                      <span className={clsx('status-badge', `status-${check.severity}`)}>
                        {check.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-2 py-1 rounded-full text-xs font-medium', {
                        'bg-green-500/20 text-green-300': check.status === 'pass',
                        'bg-red-500/20 text-red-300': check.status === 'fail',
                        'bg-yellow-500/20 text-yellow-300': check.status === 'warn',
                        'bg-slate-500/20 text-slate-400': check.status === 'error',
                      })}>
                        {check.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs font-mono text-slate-300">
                      {check.current_value ?? '—'}
                    </td>
                    <td className="px-6 py-4 text-xs font-mono text-slate-400">
                      {check.expected_value ?? '—'}
                    </td>
                    <td className="px-6 py-4">
                      {check.status === 'fail' && check.auto_remediable && (
                        <button
                          disabled={remediatingId === check.id || remediateMut.isPending}
                          onClick={() => {
                            setRemediatingId(check.id)
                            remediateMut.mutate(check.id)
                          }}
                          className="text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                        >
                          {remediatingId === check.id ? 'Fixing…' : 'Auto-fix'}
                        </button>
                      )}
                      {check.status === 'fail' && !check.auto_remediable && (
                        <span className="text-xs text-slate-500">Manual</span>
                      )}
                    </td>
                  </tr>
                ))}
                {checks.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-6 py-8 text-center text-sm text-slate-400">
                      No scan results yet. Click "Run Scan" to start.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
