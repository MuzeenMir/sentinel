import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { complianceApi } from '../services/api'

interface Framework {
  id: string
  name: string
  description: string
  version: string
  controls_count: number
  categories: string[]
}

interface AssessmentResult {
  framework: string
  overall_score: number
  status: string
  timestamp: string
  controls_assessed: number
  controls_compliant: number
  controls_non_compliant: number
  controls_not_applicable: number
  details: AssessmentDetail[]
}

interface AssessmentDetail {
  control_id: string
  control_name: string
  category: string
  status: string
  findings: string[]
}

function scoreColor(score: number): string {
  if (score >= 90) return 'text-emerald-400'
  if (score >= 70) return 'text-yellow-400'
  return 'text-red-400'
}

function barColor(score: number): string {
  if (score >= 90) return 'bg-emerald-500'
  if (score >= 70) return 'bg-yellow-500'
  return 'bg-red-500'
}

function statusBadge(status: string): string {
  switch (status) {
    case 'compliant':
      return 'status-badge status-compliant'
    case 'non_compliant':
      return 'status-badge status-critical'
    case 'partial':
      return 'status-badge status-medium'
    default:
      return 'status-badge'
  }
}

export function Compliance() {
  const queryClient = useQueryClient()
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [assessmentResult, setAssessmentResult] = useState<AssessmentResult | null>(null)
  const [showDetails, setShowDetails] = useState(false)

  const { data: frameworksResponse, isLoading, error } = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: () => complianceApi.getFrameworks(),
  })

  const assessMutation = useMutation({
    mutationFn: (framework: string) => complianceApi.runAssessment(framework),
    onSuccess: (response) => {
      setAssessmentResult(response.data)
      setShowDetails(true)
      queryClient.invalidateQueries({ queryKey: ['compliance-frameworks'] })
    },
  })

  const frameworks: Framework[] = frameworksResponse?.data?.frameworks ?? []

  const overallScore = frameworks.length > 0
    ? Math.round(frameworks.reduce((acc, _fw, _i) => acc + 0, 0) / Math.max(frameworks.length, 1))
    : 0

  const handleRunAssessment = (frameworkId: string) => {
    setSelectedFramework(frameworkId)
    assessMutation.mutate(frameworkId)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-400" />
        <span className="ml-3 text-slate-400">Loading compliance data...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="card p-6">
        <div className="text-center">
          <h3 className="text-lg font-semibold text-red-400">Failed to load compliance data</h3>
          <p className="text-sm text-slate-400 mt-2">
            Ensure the compliance-engine service is running and accessible via the API gateway.
          </p>
          <button
            className="btn btn-primary mt-4 text-sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ['compliance-frameworks'] })}
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="card p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-semibold">Compliance Overview</h3>
            <p className="text-sm text-slate-400">
              Policy coverage across {frameworks.length} regulatory frameworks.
            </p>
          </div>
          {assessmentResult && (
            <div className="text-sm text-slate-300">
              <span className={`text-2xl font-semibold ${scoreColor(assessmentResult.overall_score)}`}>
                {assessmentResult.overall_score}%
              </span>{' '}
              last assessment score
            </div>
          )}
        </div>
        {assessmentResult && (
          <div className="mt-4">
            <div className="w-full bg-slate-800/80 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${barColor(assessmentResult.overall_score)}`}
                style={{ width: `${assessmentResult.overall_score}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {assessmentResult.controls_compliant}/{assessmentResult.controls_assessed} controls
              compliant ({assessmentResult.framework})
            </p>
          </div>
        )}
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {frameworks.map((fw) => (
          <div key={fw.id} className="card p-6">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold">{fw.name}</h3>
            </div>
            <p className="text-xs text-slate-400 mb-3">{fw.description}</p>
            <div className="flex items-center justify-between text-sm text-slate-400 mb-3">
              <span>{fw.controls_count} controls</span>
              <span className="text-xs">v{fw.version}</span>
            </div>
            <button
              className="btn btn-primary w-full text-sm"
              onClick={() => handleRunAssessment(fw.id)}
              disabled={assessMutation.isPending && selectedFramework === fw.id}
            >
              {assessMutation.isPending && selectedFramework === fw.id
                ? 'Running...'
                : 'Run Assessment'}
            </button>
          </div>
        ))}
      </div>

      {/* Assessment Results */}
      {showDetails && assessmentResult && (
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <h3 className="font-semibold">
              Assessment Results: {assessmentResult.framework}
            </h3>
            <div className="flex items-center gap-3">
              <span className={`text-lg font-bold ${scoreColor(assessmentResult.overall_score)}`}>
                {assessmentResult.overall_score}%
              </span>
              <button
                className="text-sm text-slate-400 hover:text-slate-200"
                onClick={() => setShowDetails(false)}
              >
                Close
              </button>
            </div>
          </div>
          <div className="px-6 py-3 border-b border-slate-800/80">
            <div className="flex gap-6 text-sm">
              <span className="text-emerald-400">
                {assessmentResult.controls_compliant} Compliant
              </span>
              <span className="text-red-400">
                {assessmentResult.controls_non_compliant} Non-compliant
              </span>
              <span className="text-slate-400">
                {assessmentResult.controls_not_applicable} N/A
              </span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">Control</th>
                  <th className="px-6 py-3 text-left font-medium">Category</th>
                  <th className="px-6 py-3 text-left font-medium">Status</th>
                  <th className="px-6 py-3 text-left font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {(assessmentResult.details ?? []).map((detail) => (
                  <tr
                    key={detail.control_id}
                    className="border-b border-slate-800/50 hover:bg-slate-900/60"
                  >
                    <td className="px-6 py-4">
                      <div className="text-sm font-medium">{detail.control_id}</div>
                      <div className="text-xs text-slate-400">{detail.control_name}</div>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400">{detail.category}</td>
                    <td className="px-6 py-4">
                      <span className={statusBadge(detail.status)}>
                        {detail.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400">
                      {detail.findings?.length > 0 ? (
                        <ul className="list-disc pl-4 space-y-1">
                          {detail.findings.map((f, i) => (
                            <li key={i}>{f}</li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-emerald-400">No issues</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Assessment error */}
      {assessMutation.isError && (
        <div className="card p-6 border border-red-500/30">
          <p className="text-red-400 text-sm">
            Assessment failed. Ensure the compliance-engine service is available.
          </p>
        </div>
      )}
    </div>
  )
}
