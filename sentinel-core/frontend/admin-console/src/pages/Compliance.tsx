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
  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {mockComplianceData.frameworks.map((fw) => (
          <div key={fw.id} className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold">{fw.name}</h3>
              <span className={`text-2xl font-bold ${
                fw.score >= 90 ? 'text-green-400' : 
                fw.score >= 70 ? 'text-yellow-400' : 'text-red-400'
              }`}>
                {fw.score}%
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
              <div 
                className={`h-2 rounded-full ${
                  fw.score >= 90 ? 'bg-green-500' : 
                  fw.score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                }`}
                style={{ width: `${fw.score}%` }}
              />
            </div>
            <p className="text-sm text-gray-400">
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
              <tr className="border-b border-gray-700">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Framework</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {mockComplianceData.recentAssessments.map((assessment) => (
                <tr key={assessment.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="px-6 py-4 text-sm font-mono">{assessment.id}</td>
                  <td className="px-6 py-4 text-sm">{assessment.framework}</td>
                  <td className="px-6 py-4 text-sm font-bold">{assessment.score}%</td>
                  <td className="px-6 py-4 text-sm text-gray-400">{assessment.date}</td>
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
