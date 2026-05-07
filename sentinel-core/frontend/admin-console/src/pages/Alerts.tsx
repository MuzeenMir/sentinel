import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bell, Filter } from "lucide-react";
import { alertApi } from "../services/api";
import type { Alert } from "../types";

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
  };
  return map[severity] ?? "badge-info";
}

function statusBadge(status: string) {
  const map: Record<string, string> = {
    new: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    acknowledged: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    resolved: "bg-green-500/20 text-green-400 border-green-500/30",
    ignored: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return `badge border ${map[status] ?? ""}`;
}

export function Alerts() {
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  const params: Record<string, string> = {};
  if (severityFilter) params.severity = severityFilter;
  if (statusFilter) params.status = statusFilter;

  const { data, isLoading, isError } = useQuery({
    queryKey: ["alerts", params],
    queryFn: () => alertApi.getAlerts(params).then((r) => r.data),
  });

  const statsQuery = useQuery({
    queryKey: ["alert-stats"],
    queryFn: () => alertApi.getStats().then((r) => r.data),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["alerts"] });
    queryClient.invalidateQueries({ queryKey: ["alert-stats"] });
  };

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => alertApi.acknowledge(id),
    onSuccess: invalidate,
  });

  const resolveMutation = useMutation({
    mutationFn: (id: string) => alertApi.resolve(id),
    onSuccess: invalidate,
  });

  const ignoreMutation = useMutation({
    mutationFn: (id: string) => alertApi.ignore(id),
    onSuccess: invalidate,
  });

  const alerts: Alert[] = data?.alerts ?? [];
  const alertStats = statsQuery.data;

  const statCards = alertStats
    ? [
        {
          label: "New",
          value: alertStats.new,
          color: "text-blue-400",
          bg: "bg-blue-500/10",
        },
        {
          label: "Acknowledged",
          value: alertStats.acknowledged,
          color: "text-yellow-400",
          bg: "bg-yellow-500/10",
        },
        {
          label: "Resolved",
          value: alertStats.resolved,
          color: "text-green-400",
          bg: "bg-green-500/10",
        },
        {
          label: "Ignored",
          value: alertStats.ignored,
          color: "text-slate-400",
          bg: "bg-slate-500/10",
        },
      ]
    : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
        </div>
      </div>

      {statCards && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {statCards.map((card) => (
            <div key={card.label} className="card p-4">
              <p className="text-sm text-slate-400">{card.label}</p>
              <p className={`mt-1 text-2xl font-bold ${card.color}`}>
                {card.value}
              </p>
            </div>
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Filter className="h-4 w-4 text-slate-400" />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="select-field"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="select-field"
        >
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="ignored">Ignored</option>
        </select>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading alerts…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">
            Failed to load alerts. Please try again.
          </p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No alerts match the current filters.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Severity</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">Source</th>
                  <th className="table-header">Description</th>
                  <th className="table-header">Time</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/30">
                    <td className="table-cell">
                      <span className={severityBadge(alert.severity)}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="table-cell font-medium text-white">
                      {alert.type}
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {alert.source}
                    </td>
                    <td className="table-cell max-w-xs truncate">
                      {alert.description}
                    </td>
                    <td className="table-cell text-slate-400 text-xs whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleString()}
                    </td>
                    <td className="table-cell">
                      <span className={statusBadge(alert.status)}>
                        {alert.status}
                      </span>
                    </td>
                    <td className="table-cell">
                      <div className="flex items-center gap-2">
                        {alert.status === "new" && (
                          <>
                            <button
                              onClick={() =>
                                acknowledgeMutation.mutate(alert.id)
                              }
                              className="text-xs text-yellow-400 hover:text-yellow-300"
                            >
                              Acknowledge
                            </button>
                            <button
                              onClick={() => resolveMutation.mutate(alert.id)}
                              className="text-xs text-green-400 hover:text-green-300"
                            >
                              Resolve
                            </button>
                            <button
                              onClick={() => ignoreMutation.mutate(alert.id)}
                              className="text-xs text-slate-400 hover:text-slate-300"
                            >
                              Ignore
                            </button>
                          </>
                        )}
                        {alert.status === "acknowledged" && (
                          <button
                            onClick={() => resolveMutation.mutate(alert.id)}
                            className="text-xs text-green-400 hover:text-green-300"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
