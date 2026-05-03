import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Plus, X } from "lucide-react";
import { policyApi } from "../services/api";
import type { Policy, PolicyCreateRequest } from "../types";

const EMPTY_FORM: PolicyCreateRequest = {
  name: "",
  description: "",
  action: "deny",
  priority: 100,
  source_cidr: "",
  destination_cidr: "",
  protocol: "tcp",
  port_range: "",
};

export function Policies() {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [editPolicy, setEditPolicy] = useState<Policy | null>(null);
  const [form, setForm] = useState<PolicyCreateRequest>({ ...EMPTY_FORM });
  const [validationError, setValidationError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policyApi.getPolicies().then((r) => r.data),
  });

  const policies: Policy[] = data?.policies ?? [];
  const denyCount = policies.filter((p) => p.action === "deny").length;
  const allowCount = policies.filter((p) => p.action === "allow").length;

  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["policies"] });

  const createMutation = useMutation({
    mutationFn: (payload: PolicyCreateRequest) =>
      policyApi.createPolicy(payload),
    onSuccess: () => {
      invalidate();
      setShowCreate(false);
      setForm({ ...EMPTY_FORM });
      setValidationError("");
      setSuccessMsg("Policy created successfully.");
      setTimeout(() => setSuccessMsg(""), 5000);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Record<string, unknown>;
    }) => policyApi.updatePolicy(id, payload),
    onSuccess: () => {
      invalidate();
      setEditPolicy(null);
    },
  });

  const openCreate = () => {
    setForm({ ...EMPTY_FORM });
    setValidationError("");
    setShowCreate(true);
  };

  const closeModal = () => {
    setShowCreate(false);
    setEditPolicy(null);
    setValidationError("");
  };

  const openEdit = (policy: Policy) => {
    setForm({
      name: policy.name,
      description: policy.description,
      action: policy.action,
      priority: policy.priority,
      source_cidr: policy.source_cidr,
      destination_cidr: policy.destination_cidr,
      protocol: policy.protocol,
      port_range: policy.port_range,
    });
    setValidationError("");
    setEditPolicy(policy);
  };

  const handleCreate = () => {
    if (!form.name.trim()) {
      setValidationError("Policy name is required");
      return;
    }
    createMutation.mutate(form);
  };

  const handleUpdate = () => {
    if (!editPolicy) return;
    updateMutation.mutate({ id: editPolicy.id, payload: { ...form } });
  };

  const handleDisable = (id: string) => {
    updateMutation.mutate({ id, payload: { is_active: false } });
  };

  const renderModal = (
    title: string,
    onSubmit: () => void,
    submitLabel: string,
  ) => (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="card w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <button
            onClick={closeModal}
            className="text-slate-400 hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {validationError && (
          <p className="text-sm text-red-400 mb-3">{validationError}</p>
        )}

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-slate-400 mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className="input-field"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1">
              Description
            </label>
            <input
              type="text"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              className="input-field"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Action
              </label>
              <select
                value={form.action}
                onChange={(e) =>
                  setForm({
                    ...form,
                    action: e.target.value as "allow" | "deny",
                  })
                }
                className="select-field w-full"
              >
                <option value="deny">Deny</option>
                <option value="allow">Allow</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Priority
              </label>
              <input
                type="number"
                value={form.priority}
                onChange={(e) =>
                  setForm({ ...form, priority: Number(e.target.value) })
                }
                className="input-field"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Source CIDR
              </label>
              <input
                type="text"
                value={form.source_cidr ?? ""}
                onChange={(e) =>
                  setForm({ ...form, source_cidr: e.target.value })
                }
                className="input-field"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Destination CIDR
              </label>
              <input
                type="text"
                value={form.destination_cidr ?? ""}
                onChange={(e) =>
                  setForm({ ...form, destination_cidr: e.target.value })
                }
                className="input-field"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Protocol
              </label>
              <select
                value={form.protocol ?? "tcp"}
                onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                className="select-field w-full"
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">Any</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">
                Port Range
              </label>
              <input
                type="text"
                value={form.port_range ?? ""}
                onChange={(e) =>
                  setForm({ ...form, port_range: e.target.value })
                }
                className="input-field"
              />
            </div>
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button onClick={closeModal} className="btn-secondary">
            Cancel
          </button>
          <button onClick={onSubmit} className="btn-primary">
            {submitLabel}
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Active Policies</h1>
        </div>
        <button onClick={openCreate} className="btn-primary gap-2">
          <Plus className="h-4 w-4" aria-hidden="true" />
          <span>+ Create Policy</span>
        </button>
      </div>

      {successMsg && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3 text-sm text-green-400">
          {successMsg}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="card p-4">
          <p className="text-sm text-slate-400">Total Policies</p>
          <p className="mt-1 text-2xl font-bold text-white">
            {policies.length}
          </p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">DENY Rules</p>
          <p className="mt-1 text-2xl font-bold text-red-400">{denyCount}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">ALLOW Rules</p>
          <p className="mt-1 text-2xl font-bold text-green-400">{allowCount}</p>
        </div>
      </div>

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading policies…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">
            Failed to load policies. Please try again.
          </p>
        </div>
      ) : policies.length === 0 ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">
            No policies available. Create one to get started.
          </p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Name</th>
                  <th className="table-header">Action</th>
                  <th className="table-header">Source</th>
                  <th className="table-header">Destination</th>
                  <th className="table-header">Port</th>
                  <th className="table-header">Priority</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {policies.map((policy) => (
                  <tr key={policy.id} className="hover:bg-slate-800/30">
                    <td className="table-cell font-medium text-white">
                      {policy.name}
                    </td>
                    <td className="table-cell">
                      <span
                        className={`badge border ${
                          policy.action === "deny"
                            ? "bg-red-500/20 text-red-400 border-red-500/30"
                            : "bg-green-500/20 text-green-400 border-green-500/30"
                        }`}
                      >
                        {policy.action.toUpperCase()}
                      </span>
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {policy.source_cidr}
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {policy.destination_cidr}
                    </td>
                    <td className="table-cell font-mono text-xs">
                      {policy.port_range}
                    </td>
                    <td className="table-cell">{policy.priority}</td>
                    <td className="table-cell">
                      <span
                        className={`badge border ${
                          policy.is_active
                            ? "bg-green-500/20 text-green-400 border-green-500/30"
                            : "bg-slate-500/20 text-slate-400 border-slate-500/30"
                        }`}
                      >
                        {policy.is_active ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="table-cell">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => openEdit(policy)}
                          className="text-xs text-cyan-400 hover:text-cyan-300"
                        >
                          Edit
                        </button>
                        {policy.is_active && (
                          <button
                            onClick={() => handleDisable(policy.id)}
                            className="text-xs text-yellow-400 hover:text-yellow-300"
                          >
                            Disable
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

      {showCreate &&
        renderModal("Create Policy", handleCreate, "Create Policy")}
      {editPolicy && renderModal("Edit Policy", handleUpdate, "Update Policy")}
    </div>
  );
}
