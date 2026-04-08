import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle, Play, FileWarning } from 'lucide-react'
import { complianceApi, type ComplianceFrameworkId } from '../services/api'
import type { Framework, ComplianceGap } from '../types'

const FRAMEWORK_IDS: ComplianceFrameworkId[] = ['GDPR', 'HIPAA', 'PCI-DSS', 'NIST', 'SOC2']

function scoreColor(score: number) {
  if (score >= 90) return 'text-green-400'
  if (score >= 70) return 'text-yellow-400'
  return 'text-red-400'
}

function scoreBg(score: number) {
  if (score >= 90) return 'bg-green-500'
  if (score >= 70) return 'bg-yellow-500'
  return 'bg-red-500'
}

export function Compliance() {
  const queryClient = useQueryClient()
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFrameworkId | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => complianceApi.getFrameworks().then((r) => r.data),
  })

  const gapQuery = useQuery({
    queryKey: ['gap-analysis', selectedFramework],
    queryFn: () => complianceApi.getGapAnalysis(selectedFramework!).then((r) => r.data),
    enabled: !!selectedFramework,
  })

  const assessMutation = useMutation({
    mutationFn: (framework: ComplianceFrameworkId) => complianceApi.runAssessment(framework),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['frameworks'] })
      queryClient.invalidateQueries({ queryKey: ['gap-analysis'] })
    },
  })

  const frameworks: Framework[] = data?.frameworks ?? data ?? []
  const gaps: ComplianceGap[] = gapQuery.data?.gaps ?? gapQuery.data ?? []

  const frameworkCards: Framework[] =
    frameworks.length > 0
      ? frameworks
      : FRAMEWORK_IDS.map((id): Framework => ({
          id,
          name: id,
          description: '',
          version: '',
          score: 0,
        }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <CheckCircle className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Compliance</h1>
        </div>
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
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
            {frameworkCards.map((fw) => {
              const score = fw.score ?? 0
              return (
                <div
                  key={fw.id}
                  className={`card p-5 cursor-pointer transition-all hover:border-cyan-500/30 ${
                    selectedFramework === fw.id
                      ? 'border-cyan-500/50 ring-1 ring-cyan-500/20'
                      : ''
                  }`}
                  onClick={() => setSelectedFramework(fw.id as ComplianceFrameworkId)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-bold text-white">{fw.name || fw.id}</h3>
                  </div>
                  <div className="relative h-2 rounded-full bg-slate-700 mb-2">
                    <div
                      className={`absolute inset-y-0 left-0 rounded-full ${scoreBg(score)}`}
                      style={{ width: `${score}%` }}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className={`text-2xl font-bold ${scoreColor(score)}`}>{score}%</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        assessMutation.mutate(fw.id as ComplianceFrameworkId)
                      }}
                      disabled={assessMutation.isPending}
                      className="rounded-lg bg-slate-700 p-1.5 text-slate-400 hover:bg-slate-600 hover:text-white disabled:opacity-50"
                      title="Run assessment"
                    >
                      <Play className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  {fw.last_assessed && (
                    <p className="mt-2 text-xs text-slate-500">
                      Last: {new Date(fw.last_assessed).toLocaleDateString()}
                    </p>
                  )}
                </div>
              )
            })}
          </div>

          {selectedFramework && (
            <div className="card p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <FileWarning className="h-5 w-5 text-yellow-400" />
                  <h2 className="text-lg font-semibold text-white">
                    Gap Analysis — {selectedFramework}
                  </h2>
                </div>
                <button
                  onClick={() => assessMutation.mutate(selectedFramework)}
                  disabled={assessMutation.isPending}
                  className="btn-primary text-sm gap-2"
                >
                  <Play className="h-4 w-4" /> Run Assessment
                </button>
              </div>

              {gapQuery.isLoading ? (
                <p className="text-sm text-slate-400">Loading gap analysis…</p>
              ) : gapQuery.isError ? (
                <p className="text-sm text-red-400">Failed to load gap analysis.</p>
              ) : gaps.length === 0 ? (
                <p className="text-sm text-green-400">
                  No compliance gaps found. All controls are passing.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="table-header">Control</th>
                        <th className="table-header">Title</th>
                        <th className="table-header">Severity</th>
                        <th className="table-header">Status</th>
                        <th className="table-header">Recommendation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                      {gaps.map((gap) => (
                        <tr key={gap.control_id} className="hover:bg-slate-800/30">
                          <td className="table-cell font-mono text-xs text-cyan-400">
                            {gap.control_id}
                          </td>
                          <td className="table-cell font-medium text-white">{gap.title}</td>
                          <td className="table-cell">
                            <span className={`badge-${gap.severity}`}>{gap.severity}</span>
                          </td>
                          <td className="table-cell">{gap.status}</td>
                          <td className="table-cell text-sm text-slate-400">
                            {gap.recommendation}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
