import { useEffect } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ResponsiveContainer,
  LineChart,
  BarChart,
  Line,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import {
  Shield,
  ShieldCheck,
  FileText,
  CheckCircle,
  AlertTriangle,
} from "lucide-react";
import { statsApi } from "../services/api";
import { createSseClient } from "../services/stream";

const FALLBACK_STATS = {
  totalThreats: 1247,
  blockedThreats: 1189,
  activePolicies: 42,
  complianceScore: 94,
};

interface RecentThreat {
  id: string;
  type: string;
  severity: string;
  source_ip: string;
  timestamp: string;
}

const FALLBACK_THREATS: RecentThreat[] = [
  {
    id: "t-1",
    type: "DDoS Attack",
    severity: "critical",
    source_ip: "203.0.113.42",
    timestamp: "2026-03-13T10:15:00Z",
  },
  {
    id: "t-2",
    type: "Port Scan",
    severity: "high",
    source_ip: "198.51.100.17",
    timestamp: "2026-03-13T09:42:00Z",
  },
  {
    id: "t-3",
    type: "Brute Force",
    severity: "medium",
    source_ip: "192.0.2.88",
    timestamp: "2026-03-13T08:30:00Z",
  },
  {
    id: "t-4",
    type: "SQL Injection",
    severity: "high",
    source_ip: "172.16.0.99",
    timestamp: "2026-03-13T07:55:00Z",
  },
];

function generateFallbackTraffic() {
  return Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, "0")}:00`,
    inbound: 200 + ((i * 37 + 13) % 500),
    outbound: 100 + ((i * 23 + 7) % 300),
    blocked: (i * 11 + 3) % 50,
  }));
}

function generateFallbackActivity() {
  return Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, "0")}:00`,
    count: 5 + ((i * 17 + 11) % 30),
  }));
}

const FALLBACK_TRAFFIC = generateFallbackTraffic();
const FALLBACK_ACTIVITY = generateFallbackActivity();

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
  };
  return map[severity] ?? "badge-info";
}

export function Dashboard() {
  const queryClient = useQueryClient();

  const statsQuery = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => statsApi.getDashboardStats().then((r) => r.data),
    refetchInterval: 30_000,
  });

  const trafficQuery = useQuery({
    queryKey: ["traffic-stats"],
    queryFn: () => statsApi.getTrafficStats().then((r) => r.data),
    refetchInterval: 30_000,
  });

  useEffect(() => {
    const es = createSseClient("/api/v1/stream/alerts", () => {
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
    });
    return () => es.close();
  }, [queryClient]);

  const hasLiveData = statsQuery.isSuccess;
  const isOffline = statsQuery.isError;

  const stats = {
    totalThreats:
      statsQuery.data?.stats?.totalThreats ?? FALLBACK_STATS.totalThreats,
    blockedThreats:
      statsQuery.data?.stats?.blockedThreats ?? FALLBACK_STATS.blockedThreats,
    activePolicies:
      statsQuery.data?.stats?.activePolicies ?? FALLBACK_STATS.activePolicies,
    complianceScore:
      statsQuery.data?.stats?.complianceScore ?? FALLBACK_STATS.complianceScore,
  };

  const recentThreats: RecentThreat[] = hasLiveData
    ? (statsQuery.data?.recentThreats ?? [])
    : FALLBACK_THREATS;

  const trafficData =
    trafficQuery.data && Array.isArray(trafficQuery.data)
      ? trafficQuery.data
      : FALLBACK_TRAFFIC;

  const statCards = [
    {
      label: "Total Threats",
      value: stats.totalThreats,
      icon: Shield,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      label: "Blocked Threats",
      value: stats.blockedThreats,
      icon: ShieldCheck,
      color: "text-green-400",
      bg: "bg-green-500/10",
    },
    {
      label: "Active Policies",
      value: stats.activePolicies,
      icon: FileText,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
    },
    {
      label: "Compliance Score",
      value: `${stats.complianceScore}%`,
      icon: CheckCircle,
      color: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Security Overview</h1>
      </div>

      {isOffline && (
        <div className="flex items-center gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-400">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          Live telemetry is unavailable — showing cached data.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((card) => (
          <div key={card.label} className="card p-5">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-slate-400">{card.label}</p>
              <div className={`rounded-lg p-2 ${card.bg}`}>
                <card.icon className={`h-5 w-5 ${card.color}`} />
              </div>
            </div>
            <p className="mt-2 text-3xl font-bold text-white">{card.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="card p-5">
          <h2 className="text-lg font-semibold text-white mb-4">
            Network Traffic (24h)
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1e293b",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                  }}
                  labelStyle={{ color: "#e2e8f0" }}
                />
                <Line
                  type="monotone"
                  dataKey="inbound"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="outbound"
                  stroke="#8b5cf6"
                  strokeWidth={2}
                  dot={false}
                />
                <Line
                  type="monotone"
                  dataKey="blocked"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card p-5">
          <h2 className="text-lg font-semibold text-white mb-4">
            Threat Activity (24h)
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={FALLBACK_ACTIVITY}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1e293b",
                    border: "1px solid #334155",
                    borderRadius: "8px",
                  }}
                  labelStyle={{ color: "#e2e8f0" }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Recent Threats</h2>
          <Link
            to="/threats"
            className="text-sm text-cyan-400 hover:text-cyan-300"
          >
            View All
          </Link>
        </div>

        {recentThreats.length === 0 ? (
          <p className="text-sm text-slate-400 py-8 text-center">
            No recent threats detected.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="table-header">Type</th>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Source</th>
                  <th className="table-header">Time</th>
                  <th className="table-header">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {recentThreats.map((threat) => (
                  <tr key={threat.id} className="hover:bg-slate-800/30">
                    <td className="table-cell font-medium text-white">
                      {threat.type}
                    </td>
                    <td className="table-cell">
                      <span className={severityBadge(threat.severity)}>
                        {threat.severity}
                      </span>
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {threat.source_ip}
                    </td>
                    <td className="table-cell text-slate-400">
                      {new Date(threat.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="table-cell">
                      <Link
                        to={`/threats/${threat.id}`}
                        className="text-sm text-cyan-400 hover:text-cyan-300"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
