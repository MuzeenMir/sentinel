import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users as UsersIcon } from "lucide-react";
import { usersApi } from "../services/api";
import { useAuthStore } from "../store/authStore";
import type { User } from "../types";

const ROLES = ["admin", "security_analyst", "analyst", "auditor", "viewer"];
const STATUSES = ["active", "inactive", "suspended"];

const ROLE_PERMISSIONS: Record<string, string> = {
  admin: "Full access — manage users, policies, settings, and all data.",
  security_analyst: "Investigate threats, triage alerts, and manage policies.",
  analyst: "Investigate threats and triage alerts.",
  auditor: "Read-only access to audit logs, compliance, and reports.",
  viewer: "Read-only access to dashboards and reports.",
};

export function Users() {
  const queryClient = useQueryClient();
  const currentUser = useAuthStore((s) => s.user);
  const [roleFilter, setRoleFilter] = useState("");
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editRole, setEditRole] = useState("");
  const [editStatus, setEditStatus] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["users", roleFilter],
    queryFn: () =>
      usersApi
        .getUsers(roleFilter ? { role: roleFilter } : undefined)
        .then((r) => r.data),
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: number;
      payload: { role?: string; status?: string };
    }) => usersApi.updateUser(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setEditingId(null);
    },
  });

  const users: User[] = data?.users ?? data ?? [];

  const openEdit = (user: User) => {
    setEditingId(user.id);
    setEditRole(user.role);
    setEditStatus(user.status);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditRole("");
    setEditStatus("");
  };

  const saveEdit = (user: User) => {
    const payload: { role?: string; status?: string } = {};
    if (editRole !== user.role) payload.role = editRole;
    if (editStatus !== user.status) payload.status = editStatus;
    if (!payload.role && !payload.status) {
      setEditingId(null);
      return;
    }
    updateMutation.mutate({ id: user.id, payload });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <UsersIcon className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Users &amp; RBAC</h1>
        </div>
      </div>

      <div className="card p-6">
        <h2 className="text-lg font-semibold text-white mb-3">
          Role Permissions
        </h2>
        <ul className="space-y-2 text-sm">
          {Object.entries(ROLE_PERMISSIONS).map(([role, desc]) => (
            <li key={role} className="flex gap-3">
              <span className="badge bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 min-w-[7rem] justify-center">
                {role}
              </span>
              <span className="text-slate-300">{desc}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="select-field"
        >
          <option value="">All roles</option>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading users…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load users.</p>
        </div>
      ) : users.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">No users found.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Username</th>
                  <th className="table-header">Email</th>
                  <th className="table-header">Role</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Created</th>
                  <th className="table-header">Last Login</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {users.map((user) => {
                  const isSelf = currentUser?.id === user.id;
                  const isEditing = editingId === user.id;
                  return (
                    <tr key={user.id} className="hover:bg-slate-800/30">
                      <td className="table-cell font-medium text-white">
                        <span>{user.username}</span>
                        {isSelf && (
                          <span className="ml-2 text-xs text-cyan-400">
                            (you)
                          </span>
                        )}
                      </td>
                      <td className="table-cell text-slate-300">
                        {user.email}
                      </td>
                      <td className="table-cell">
                        {isEditing ? (
                          <select
                            value={editRole}
                            onChange={(e) => setEditRole(e.target.value)}
                            className="select-field"
                          >
                            {ROLES.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span className="badge bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                            {user.role}
                          </span>
                        )}
                      </td>
                      <td className="table-cell">
                        {isEditing ? (
                          <select
                            value={editStatus}
                            onChange={(e) => setEditStatus(e.target.value)}
                            className="select-field"
                          >
                            {STATUSES.map((s) => (
                              <option key={s} value={s}>
                                {s}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span
                            className={`badge border ${
                              user.status === "active"
                                ? "bg-green-500/20 text-green-400 border-green-500/30"
                                : "bg-slate-500/20 text-slate-400 border-slate-500/30"
                            }`}
                          >
                            {user.status}
                          </span>
                        )}
                      </td>
                      <td className="table-cell text-xs text-slate-400">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="table-cell text-xs text-slate-400">
                        {user.last_login
                          ? new Date(user.last_login).toLocaleString()
                          : "Never"}
                      </td>
                      <td className="table-cell">
                        {isSelf ? (
                          <span className="text-slate-500">—</span>
                        ) : isEditing ? (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => saveEdit(user)}
                              className="text-xs text-green-400 hover:text-green-300"
                            >
                              Save
                            </button>
                            <button
                              onClick={cancelEdit}
                              className="text-xs text-slate-400 hover:text-slate-300"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => openEdit(user)}
                            className="text-xs text-cyan-400 hover:text-cyan-300"
                          >
                            Edit
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
