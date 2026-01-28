import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { api } from '../services/api'

// Mock data for demonstration
const mockStats = {
  totalThreats: 1247,
  blockedThreats: 1189,
  activePolicies: 42,
  complianceScore: 94,
}

const mockTrafficData = [
  { time: '00:00', inbound: 4000, outbound: 2400, threats: 12 },
  { time: '04:00', inbound: 3000, outbound: 1398, threats: 8 },
  { time: '08:00', inbound: 9800, outbound: 4300, threats: 24 },
  { time: '12:00', inbound: 12000, outbound: 6800, threats: 31 },
  { time: '16:00', inbound: 8500, outbound: 5200, threats: 18 },
  { time: '20:00', inbound: 6200, outbound: 3800, threats: 15 },
]

const mockRecentThreats = [
  { id: 1, type: 'DDoS Attack', severity: 'critical', source: '192.168.1.100', time: '2 min ago' },
  { id: 2, type: 'Port Scan', severity: 'high', source: '10.0.0.50', time: '15 min ago' },
  { id: 3, type: 'Brute Force', severity: 'medium', source: '172.16.0.25', time: '32 min ago' },
  { id: 4, type: 'SQL Injection', severity: 'high', source: '192.168.2.80', time: '1 hr ago' },
]

export function Dashboard() {
  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Threats"
          value={mockStats.totalThreats}
          change="+12%"
          changeType="negative"
          icon="🎯"
        />
        <StatCard
          title="Blocked Threats"
          value={mockStats.blockedThreats}
          change="95.3%"
          changeType="positive"
          icon="🛡️"
        />
        <StatCard
          title="Active Policies"
          value={mockStats.activePolicies}
          change="+3"
          changeType="neutral"
          icon="📋"
        />
        <StatCard
          title="Compliance Score"
          value={`${mockStats.complianceScore}%`}
          change="+2%"
          changeType="positive"
          icon="✅"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Traffic Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="font-semibold">Network Traffic (24h)</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={mockTrafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                />
                <Line type="monotone" dataKey="inbound" stroke="#3B82F6" strokeWidth={2} />
                <Line type="monotone" dataKey="outbound" stroke="#10B981" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threats Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="font-semibold">Threat Activity (24h)</h3>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={mockTrafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="time" stroke="#9CA3AF" />
                <YAxis stroke="#9CA3AF" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                />
                <Bar dataKey="threats" fill="#EF4444" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Threats Table */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h3 className="font-semibold">Recent Threats</h3>
          <a href="/threats" className="text-sm text-blue-400 hover:text-blue-300">View All</a>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase">Action</th>
              </tr>
            </thead>
            <tbody>
              {mockRecentThreats.map((threat) => (
                <tr key={threat.id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="px-6 py-4 text-sm">{threat.type}</td>
                  <td className="px-6 py-4">
                    <span className={`status-badge status-${threat.severity}`}>
                      {threat.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-gray-300">{threat.source}</td>
                  <td className="px-6 py-4 text-sm text-gray-400">{threat.time}</td>
                  <td className="px-6 py-4">
                    <button className="text-blue-400 hover:text-blue-300 text-sm">Investigate</button>
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

interface StatCardProps {
  title: string
  value: string | number
  change: string
  changeType: 'positive' | 'negative' | 'neutral'
  icon: string
}

function StatCard({ title, value, change, changeType, icon }: StatCardProps) {
  const changeColors = {
    positive: 'text-green-400',
    negative: 'text-red-400',
    neutral: 'text-gray-400',
  }

  return (
    <div className="card p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
          <p className={`text-sm mt-1 ${changeColors[changeType]}`}>{change}</p>
        </div>
        <div className="text-3xl">{icon}</div>
      </div>
    </div>
  )
}
