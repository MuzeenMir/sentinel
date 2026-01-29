const mockComplianceData = {
  frameworks: [
    { id: 'NIST', name: 'NIST CSF', score: 94, controls: 14, compliant: 13 },
    { id: 'GDPR', name: 'GDPR', score: 88, controls: 6, compliant: 5 },
    { id: 'HIPAA', name: 'HIPAA', score: 91, controls: 8, compliant: 7 },
    { id: 'PCI-DSS', name: 'PCI-DSS', score: 85, controls: 11, compliant: 9 },
  ],
  recentAssessments: [
    { id: 'A001', framework: 'NIST', score: 94, date: '2024-01-24', status: 'compliant' },
    { id: 'A002', framework: 'GDPR', score: 88, date: '2024-01-23', status: 'partial' },
    { id: 'A003', framework: 'PCI-DSS', score: 85, date: '2024-01-22', status: 'partial' },
  ]
}

export function Compliance() {
  const overallScore = Math.round(
    mockComplianceData.frameworks.reduce((acc, fw) => acc + fw.score, 0) / mockComplianceData.frameworks.length
  )
  const totalControls = mockComplianceData.frameworks.reduce((acc, fw) => acc + fw.controls, 0)
  const compliantControls = mockComplianceData.frameworks.reduce((acc, fw) => acc + fw.compliant, 0)

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <h3 className="text-lg font-semibold">Compliance Overview</h3>
            <p className="text-sm text-slate-400">Policy coverage across regulatory frameworks.</p>
          </div>
          <div className="text-sm text-slate-300">
            <span className="text-2xl font-semibold text-emerald-300">{overallScore}%</span>{' '}
            overall score
          </div>
        </div>
        <div className="mt-4">
          <div className="w-full bg-slate-800/80 rounded-full h-2">
            <div className="h-2 rounded-full bg-emerald-500" style={{ width: `${overallScore}%` }} />
          </div>
          <p className="text-xs text-slate-500 mt-2">
            {compliantControls}/{totalControls} controls compliant across all frameworks
          </p>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {mockComplianceData.frameworks.map((fw) => (
          <div key={fw.id} className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold">{fw.name}</h3>
              <span className={`text-2xl font-bold ${
                fw.score >= 90 ? 'text-emerald-400' : 
                fw.score >= 70 ? 'text-yellow-400' : 'text-red-400'
              }`}>
                {fw.score}%
              </span>
            </div>
            <div className="w-full bg-slate-800/80 rounded-full h-2 mb-2">
              <div 
                className={`h-2 rounded-full ${
                  fw.score >= 90 ? 'bg-emerald-500' : 
                  fw.score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${fw.score}%` }}
              />
            </div>
            <p className="text-sm text-slate-400">
              {fw.compliant}/{fw.controls} controls compliant
            </p>
          </div>
        ))}
      </div>

      {/* Recent Assessments */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h3 className="font-semibold">Recent Assessments</h3>
          <button className="btn btn-primary text-sm">Run Assessment</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                <th className="px-6 py-3 text-left font-medium">ID</th>
                <th className="px-6 py-3 text-left font-medium">Framework</th>
                <th className="px-6 py-3 text-left font-medium">Score</th>
                <th className="px-6 py-3 text-left font-medium">Date</th>
                <th className="px-6 py-3 text-left font-medium">Status</th>
                <th className="px-6 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockComplianceData.recentAssessments.map((assessment) => (
                <tr key={assessment.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                  <td className="px-6 py-4 text-sm font-mono">{assessment.id}</td>
                  <td className="px-6 py-4 text-sm">{assessment.framework}</td>
                  <td className="px-6 py-4 text-sm font-bold">{assessment.score}%</td>
                  <td className="px-6 py-4 text-sm text-slate-400">{assessment.date}</td>
                  <td className="px-6 py-4">
                    <span className={`status-badge ${
                      assessment.status === 'compliant' ? 'status-compliant' : 'status-medium'
                    }`}>
                      {assessment.status}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <button className="text-blue-400 hover:text-blue-300 text-sm">View Report</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
