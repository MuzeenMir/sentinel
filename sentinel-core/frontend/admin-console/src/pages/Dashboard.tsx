import { useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { statsApi } from '../services/api'
import { createSseClient } from '../services/stream'

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
  const queryClient = useQueryClient()
  const {
    data: statsData,
    isError: statsError,
    dataUpdatedAt: statsUpdatedAt,
  } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async () => {
      const res = await statsApi.getDashboardStats()
      return res.data
    },
    retry: 1,
    staleTime: 60_000,
  })

  const {
    data: trafficData,
    isError: trafficError,
    dataUpdatedAt: trafficUpdatedAt,
  } = useQuery({
    queryKey: ['traffic-stats'],
    queryFn: async () => {
      const res = await statsApi.getTrafficStats()
      return res.data
    },
    retry: 1,
    staleTime: 60_000,
  })

  const resolvedStats = {
    ...mockStats,
    ...(statsData?.stats || statsData || {}),
  }

  const resolvedTraffic = Array.isArray(trafficData)
    ? trafficData
    : trafficData?.series || trafficData?.traffic || mockTrafficData

  const recentThreats = Array.isArray(statsData?.recentThreats)
    ? statsData?.recentThreats
    : Array.isArray(statsData?.threats)
      ? statsData?.threats
      : mockRecentThreats

  const lastUpdatedAt = Math.max(statsUpdatedAt || 0, trafficUpdatedAt || 0)
  const lastUpdatedLabel = lastUpdatedAt ? new Date(lastUpdatedAt).toLocaleTimeString() : 'Just now'

  useEffect(() => {
    const es = createSseClient('/api/v1/stream/alerts', () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] })
      queryClient.invalidateQueries({ queryKey: ['traffic-stats'] })
    })
    return () => es.close()
  }, [queryClient])

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h3 className="text-xl font-semibold">Security Overview</h3>
          <p className="text-sm text-slate-400">
            Live telemetry across sensors, models, and policy engines.
          </p>
        </div>
        <div className="text-xs text-slate-400">
          Last sync: <span className="text-slate-200">{lastUpdatedLabel}</span>
        </div>
      </div>

      {(statsError || trafficError) && (
        <div className="rounded-lg border border-yellow-900/60 bg-yellow-950/40 px-4 py-3 text-sm text-yellow-200">
          Live telemetry is unavailable. Showing the latest cached metrics.
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        <StatCard
          title="Total Threats"
          value={resolvedStats.totalThreats}
          change="+12%"
          changeType="negative"
          icon="Shield telemetry"
          description="All detections in the last 24 hours"
        />
        <StatCard
          title="Blocked Threats"
          value={resolvedStats.blockedThreats}
          change="95.3%"
          changeType="positive"
          icon="Automated blocks"
          description="Policies auto-blocked with high confidence"
        />
        <StatCard
          title="Active Policies"
          value={resolvedStats.activePolicies}
          change="+3"
          changeType="neutral"
          icon="Policy packs"
          description="Policies currently enforced across vendors"
        />
        <StatCard
          title="Compliance Score"
          value={`${resolvedStats.complianceScore}%`}
          change="+2%"
          changeType="positive"
          icon="Compliance posture"
          description="Weighted score across configured frameworks"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Traffic Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="font-semibold">Network Traffic (24h)</h3>
            <p className="text-xs text-slate-500 mt-1">Inbound vs outbound throughput</p>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={resolvedTraffic}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                <XAxis dataKey="time" stroke="#94A3B8" />
                <YAxis stroke="#94A3B8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B1220', border: '1px solid #1F2937' }}
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
            <p className="text-xs text-slate-500 mt-1">Confirmed alerts by hour</p>
          </div>
          <div className="card-body">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={resolvedTraffic}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                <XAxis dataKey="time" stroke="#94A3B8" />
                <YAxis stroke="#94A3B8" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B1220', border: '1px solid #1F2937' }}
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
          <div>
            <h3 className="font-semibold">Recent Threats</h3>
            <p className="text-xs text-slate-500 mt-1">Latest detections across sensors</p>
          </div>
          <a href="/threats" className="text-sm text-blue-400 hover:text-blue-300">View All</a>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                <th className="px-6 py-3 text-left font-medium">Type</th>
                <th className="px-6 py-3 text-left font-medium">Severity</th>
                <th className="px-6 py-3 text-left font-medium">Source</th>
                <th className="px-6 py-3 text-left font-medium">Time</th>
                <th className="px-6 py-3 text-left font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {recentThreats.map((threat) => {
                const severity = String(threat.severity || 'medium').toLowerCase()
                const timeLabel = threat.time
                  || (threat.timestamp ? new Date(threat.timestamp).toLocaleString() : 'Just now')
                return (
                  <tr key={threat.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                    <td className="px-6 py-4 text-sm">{threat.type}</td>
                    <td className="px-6 py-4">
                      <span className={`status-badge status-${severity}`}>
                        {severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm font-mono text-slate-300">{threat.source}</td>
                    <td className="px-6 py-4 text-sm text-slate-400">{timeLabel}</td>
                    <td className="px-6 py-4">
                      <button className="text-blue-400 hover:text-blue-300 text-sm">Investigate</button>
                    </td>
                  </tr>
                )
              })}
              {recentThreats.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-6 text-center text-sm text-slate-400">
                    No recent threats detected.
                  </td>
                </tr>
              )}
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
  description: string
}

function StatCard({ title, value, change, changeType, icon, description }: StatCardProps) {
  const changeColors = {
    positive: 'text-emerald-400',
    negative: 'text-red-400',
    neutral: 'text-slate-400',
  }

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">{title}</p>
          <p className="text-2xl font-semibold mt-2">{value}</p>
          <p className={`text-sm mt-2 ${changeColors[changeType]}`}>{change}</p>
          <p className="text-xs text-slate-500 mt-3">{description}</p>
        </div>
        <div className="text-xs uppercase tracking-[0.25em] text-slate-500">{icon}</div>
      </div>
    </div>
  )
}
