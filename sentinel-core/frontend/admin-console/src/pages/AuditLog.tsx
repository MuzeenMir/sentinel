import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ClipboardList,
  Filter,
  BarChart2,
  ShieldCheck,
  ShieldAlert,
} from "lucide-react";
import { auditApi } from "../services/api";
import type { AuditEntry, AuditStats } from "../types";

const PAGE_SIZE = 50;

const CATEGORY_COLORS: Record<string, string> = {
  auth: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  authorization: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  data_access: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  config_change: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  system: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  compliance: "bg-green-500/20 text-green-400 border-green-500/30",
  policy: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  alert: "bg-red-500/20 text-red-400 border-red-500/30",
};

function categoryBadge(category: string) {
  const cls =
    CATEGORY_COLORS[category] ??
    "bg-slate-600/30 text-slate-300 border-slate-600/50";
  return <span className={`badge border ${cls}`}>{category}</span>;
}

export function AuditLog() {
  const [category, setCategory] = useState("");
  const [actor, setActor] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [page, setPage] = useState(0);
  const [showStats, setShowStats] = useState(false);
  const [verifyResult, setVerifyResult] = useState<
    { id: string; valid: boolean }[] | null
  >(null);

  const offset = page * PAGE_SIZE;

  const eventsQuery = useQuery({
    queryKey: ["audit-events", category, actor, startDate, endDate, page],
    queryFn: () =>
      auditApi
        .getEvents({
          ...(category ? { category } : {}),
          ...(actor ? { actor } : {}),
          ...(startDate
            ? { start_time: new Date(startDate).getTime() / 1000 }
            : {}),
          ...(endDate
            ? { end_time: new Date(endDate + "T23:59:59").getTime() / 1000 }
            : {}),
          limit: PAGE_SIZE,
          offset,
        })
        .then((r) => r.data),
  });

  const statsQuery = useQuery<AuditStats>({
    queryKey: ["audit-stats"],
    queryFn: () => auditApi.getStats().then((r) => r.data),
    enabled: showStats,
  });

  const categoriesQuery = useQuery({
    queryKey: ["audit-categories"],
    queryFn: () => auditApi.getCategories().then((r) => r.data),
  });

  const events: AuditEntry[] =
    eventsQuery.data?.events ?? eventsQuery.data ?? [];
  const categories: string[] = categoriesQuery.data?.categories ?? [];

  const handleVerifyPage = async () => {
    if (events.length === 0) return;
    try {
      const res = await auditApi.verifyIntegrity(
        events as unknown as Record<string, unknown>[],
      );
      setVerifyResult(res.data.results);
    } catch {
      setVerifyResult(null);
    }
  };

  const verifyMap = verifyResult
    ? Object.fromEntries(verifyResult.map((r) => [r.id, r.valid]))
    : null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <ClipboardList className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Audit Log</h1>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowStats(!showStats)}
            className={`btn-secondary gap-2 ${showStats ? "border-cyan-500/50 text-cyan-400" : ""}`}
          >
            <BarChart2 className="h-4 w-4" /> Stats
          </button>
          <button onClick={handleVerifyPage} className="btn-secondary gap-2">
            <ShieldCheck className="h-4 w-4" /> Verify Page
          </button>
        </div>
      </div>

      {/* Stats panel */}
      {showStats && (
        <div className="card p-6">
          {statsQuery.isLoading ? (
            <p className="text-slate-400 text-sm">Loading stats…</p>
          ) : statsQuery.data ? (
            <div>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-white">
                  Audit Statistics
                </h2>
                <span className="text-sm text-slate-400">
                  Retention: {statsQuery.data.retention_days} days
                </span>
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-lg bg-slate-800 p-4">
                  <p className="text-xs text-slate-400">Total Events</p>
                  <p className="text-2xl font-bold text-white mt-1">
                    {statsQuery.data.total_events.toLocaleString()}
                  </p>
                </div>
                {Object.entries(statsQuery.data.by_category).map(
                  ([cat, count]) => (
                    <div key={cat} className="rounded-lg bg-slate-800 p-4">
                      <p className="text-xs text-slate-400 capitalize">{cat}</p>
                      <p className="text-xl font-bold text-white mt-1">
                        {count.toLocaleString()}
                      </p>
                    </div>
                  ),
                )}
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Integrity verify result banner */}
      {verifyMap && (
        <div className="card p-4">
          <div className="flex items-center gap-2 mb-3">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-medium text-white">
              Integrity Verification
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {verifyResult!.map((r) => (
              <span
                key={r.id}
                className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs border ${
                  r.valid
                    ? "bg-green-500/10 text-green-400 border-green-500/20"
                    : "bg-red-500/10 text-red-400 border-red-500/20"
                }`}
              >
                {r.valid ? (
                  <ShieldCheck className="h-3 w-3" />
                ) : (
                  <ShieldAlert className="h-3 w-3" />
                )}
                {r.id.slice(0, 16)}…
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap items-end gap-4">
          <Filter className="h-4 w-4 text-slate-400 self-center" />
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Category
            </label>
            <select
              value={category}
              onChange={(e) => {
                setCategory(e.target.value);
                setPage(0);
              }}
              className="select-field"
            >
              <option value="">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">Actor</label>
            <input
              type="text"
              value={actor}
              onChange={(e) => {
                setActor(e.target.value);
                setPage(0);
              }}
              placeholder="user:42 or system"
              className="input-field text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">From</label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => {
                setStartDate(e.target.value);
                setPage(0);
              }}
              className="input-field text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">To</label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => {
                setEndDate(e.target.value);
                setPage(0);
              }}
              className="input-field text-sm"
            />
          </div>
          {(category || actor || startDate || endDate) && (
            <button
              onClick={() => {
                setCategory("");
                setActor("");
                setStartDate("");
                setEndDate("");
                setPage(0);
              }}
              className="btn-secondary text-xs"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {eventsQuery.isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading audit log…</p>
        </div>
      ) : eventsQuery.isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load audit log.</p>
        </div>
      ) : events.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No audit events found.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Timestamp</th>
                  <th className="table-header">Category</th>
                  <th className="table-header">Action</th>
                  <th className="table-header">Actor</th>
                  <th className="table-header">Resource</th>
                  <th className="table-header">Tenant</th>
                  <th className="table-header">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {events.map((event) => {
                  const valid = verifyMap ? verifyMap[event.id] : undefined;
                  return (
                    <tr key={event.id} className="hover:bg-slate-800/30">
                      <td className="table-cell text-xs text-slate-400 whitespace-nowrap">
                        {new Date(event.timestamp).toLocaleString()}
                      </td>
                      <td className="table-cell">
                        {categoryBadge(
                          (event as unknown as { category: string }).category ??
                            event.event_type ??
                            "",
                        )}
                      </td>
                      <td className="table-cell">
                        <span className="badge bg-slate-600/30 text-slate-300 border border-slate-600/50">
                          {event.action}
                        </span>
                      </td>
                      <td className="table-cell font-medium text-white text-sm">
                        {event.user ??
                          (event as unknown as { actor: string }).actor}
                      </td>
                      <td className="table-cell text-slate-300 text-sm">
                        {event.resource_type ??
                          (event as unknown as { resource: string }).resource}
                      </td>
                      <td className="table-cell text-slate-400 text-xs">
                        {(event as unknown as { tenant_id?: number | null })
                          .tenant_id ?? "—"}
                      </td>
                      <td className="table-cell">
                        {valid === undefined ? (
                          <span className="text-slate-600 text-xs">—</span>
                        ) : valid ? (
                          <ShieldCheck className="h-4 w-4 text-green-400" />
                        ) : (
                          <ShieldAlert className="h-4 w-4 text-red-400" />
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-3 border-t border-slate-700">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="btn-secondary text-xs"
            >
              Previous
            </button>
            <span className="text-sm text-slate-400">
              Page {page + 1} · {events.length} events
            </span>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={events.length < PAGE_SIZE}
              className="btn-secondary text-xs"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
