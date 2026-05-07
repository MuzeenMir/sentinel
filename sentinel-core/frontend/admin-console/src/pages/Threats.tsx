import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Shield, Filter } from "lucide-react";
import { threatApi } from "../services/api";
import type { Threat } from "../types";

function severityBadge(severity: string) {
  const map: Record<string, string> = {
    critical: "badge-critical",
    high: "badge-high",
    medium: "badge-medium",
    low: "badge-low",
  };
  return map[severity] ?? "badge-info";
}

export function Threats() {
  const navigate = useNavigate();
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["threats"],
    queryFn: () => threatApi.getThreats().then((r) => r.data),
  });

  const threats: Threat[] = data?.threats ?? data ?? [];

  const filtered = threats.filter((t) => {
    if (severityFilter && t.severity !== severityFilter) return false;
    if (typeFilter && t.type !== typeFilter) return false;
    return true;
  });

  const types = [...new Set(threats.map((t) => t.type))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Threats</h1>
        </div>
      </div>

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
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="select-field"
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading threats…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">
            Failed to load threats. Please try again.
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">
            No threats match the current filters.
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">ID</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">Severity</th>
                  <th className="table-header">Source IP</th>
                  <th className="table-header">Confidence</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {filtered.map((threat) => (
                  <tr
                    key={threat.id}
                    onClick={() => navigate(`/threats/${threat.id}`)}
                    className="cursor-pointer hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="table-cell font-mono text-xs text-cyan-400">
                      {threat.id}
                    </td>
                    <td className="table-cell font-medium text-white">
                      {threat.type}
                    </td>
                    <td className="table-cell">
                      <span className={severityBadge(threat.severity)}>
                        {threat.severity}
                      </span>
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {threat.source_ip ?? "—"}
                    </td>
                    <td className="table-cell">
                      {threat.confidence != null
                        ? `${threat.confidence}%`
                        : "—"}
                    </td>
                    <td className="table-cell">
                      <span className="badge bg-slate-600/30 text-slate-300 border border-slate-600/50">
                        {threat.status}
                      </span>
                    </td>
                    <td className="table-cell text-slate-400 text-xs">
                      {new Date(threat.timestamp).toLocaleString()}
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
