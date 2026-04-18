import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { CheckCircle, Play, X } from 'lucide-react'
import { complianceApi, type ComplianceFrameworkId } from '../services/api'
import type { Framework, AssessmentResult } from '../types'

export function Compliance() {
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => complianceApi.getFrameworks().then((r) => r.data),
  })

  const assessMutation = useMutation({
    mutationFn: (framework: ComplianceFrameworkId) =>
      complianceApi.runAssessment(framework).then((r) => r.data as AssessmentResult),
    onSuccess: (result) => setAssessment(result),
  })

  const frameworks: Framework[] = data?.frameworks ?? data ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <CheckCircle className="h-6 w-6 text-cyan-400" />
        <h1 className="text-2xl font-bold text-white">Compliance</h1>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading compliance data…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load compliance data.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {frameworks.map((fw) => (
            <div key={fw.id} className="card p-5 space-y-3">
              <div>
                <h3 className="text-base font-semibold text-white">{fw.name || fw.id}</h3>
                {fw.description && (
                  <p className="mt-1 text-sm text-slate-400">{fw.description}</p>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-500">
                {fw.version && <span>v{fw.version}</span>}
                {typeof fw.controls_count === 'number' && (
                  <span>{fw.controls_count} controls</span>
                )}
              </div>
              <button
                onClick={() => assessMutation.mutate(fw.id as ComplianceFrameworkId)}
                disabled={assessMutation.isPending}
                className="btn-primary w-full gap-2 text-sm"
              >
                <Play className="h-4 w-4" />
                Run Assessment
              </button>
            </div>
          ))}
        </div>
      )}

      {assessment && (
        <div className="card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Assessment Results</h2>
            <button
              onClick={() => setAssessment(null)}
              className="btn-secondary gap-2 text-sm"
              aria-label="Close assessment results"
            >
              <X className="h-4 w-4" />
              Close
            </button>
          </div>

          <div className="flex items-baseline gap-3">
            <span className="text-4xl font-bold text-cyan-400">
              {assessment.overall_score}%
            </span>
            <span className="text-sm text-slate-400">{assessment.framework}</span>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3">
              <p className="text-sm text-green-400">
                {assessment.controls_compliant} Compliant
              </p>
            </div>
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3">
              <p className="text-sm text-red-400">
                {assessment.controls_non_compliant} Non-compliant
              </p>
            </div>
            <div className="rounded-lg border border-slate-600 bg-slate-700/30 px-4 py-3">
              <p className="text-sm text-slate-300">
                {assessment.controls_not_applicable} N/A
              </p>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="table-header">Control</th>
                  <th className="table-header">Name</th>
                  <th className="table-header">Category</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {assessment.details.map((d) => (
                  <tr key={d.control_id} className="hover:bg-slate-800/30">
                    <td className="table-cell font-mono text-xs text-cyan-400">
                      {d.control_id}
                    </td>
                    <td className="table-cell font-medium text-white">{d.control_name}</td>
                    <td className="table-cell text-slate-400">{d.category}</td>
                    <td className="table-cell">
                      <span
                        className={
                          d.status === 'compliant'
                            ? 'text-green-400'
                            : d.status === 'non_compliant'
                            ? 'text-red-400'
                            : 'text-slate-400'
                        }
                      >
                        {d.status}
                      </span>
                    </td>
                    <td className="table-cell text-sm text-slate-400">
                      {d.findings.join('; ')}
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
