import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { policyApi } from '../services/api'
import type { Policy, PolicyAction, PolicyCreateRequest } from '../types'

const emptyPolicy: PolicyCreateRequest = {
  name: '',
  description: '',
  source_cidr: '',
  destination_cidr: '',
  protocol: 'tcp',
  port_range: '',
  action: 'deny',
  priority: 100,
}

export function Policies() {
  const queryClient = useQueryClient()
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<PolicyCreateRequest>(emptyPolicy)
  const [message, setMessage] = useState<string | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['policies'],
    queryFn: async () => (await policyApi.getPolicies()).data,
    retry: 1,
  })

  const apiPolicies: Policy[] = Array.isArray(data?.policies)
    ? data.policies
    : Array.isArray(data)
      ? data
      : []

  const policies = useMemo(() => apiPolicies, [apiPolicies])

  const createMutation = useMutation({
    mutationFn: (payload: PolicyCreateRequest) => policyApi.createPolicy(payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['policies'] })
      setMessage('Policy created successfully.')
      setShowCreateModal(false)
      setForm(emptyPolicy)
    },
    onError: () => {
      setMessage('Failed to create policy. Please check inputs or try again.')
    },
  })

  const updateMutation = useMutation({
    mutationFn: (payload: { id: string; data: Record<string, unknown> }) =>
      policyApi.updatePolicy(payload.id, payload.data),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['policies'] })
      setMessage('Policy updated successfully.')
      setShowCreateModal(false)
      setEditingId(null)
      setForm(emptyPolicy)
    },
    onError: () => {
      setMessage('Failed to update policy.')
    },
  })

  const handleOpenCreate = () => {
    setEditingId(null)
    setForm(emptyPolicy)
    setShowCreateModal(true)
  }

  const handleOpenEdit = (policy: Policy) => {
    setEditingId(policy.id)
    setForm({
      name: policy.name,
      description: policy.description || '',
      source_cidr: policy.source_cidr || '',
      destination_cidr: policy.destination_cidr || '',
      protocol: policy.protocol || 'tcp',
      port_range: policy.port_range || '',
      action: policy.action || 'deny',
      priority: policy.priority || 100,
    })
    setShowCreateModal(true)
  }

  const handleSubmit = () => {
    if (!form.name.trim()) {
      setMessage('Policy name is required.')
      return
    }
    if (editingId) {
      updateMutation.mutate({ id: editingId, data: form })
    } else {
      createMutation.mutate(form)
    }
  }

  const handleDisable = (policy: Policy) => {
    updateMutation.mutate({ id: policy.id, data: { is_active: false } })
  }

  const stats = useMemo(() => {
    const total = policies.length
    const deny = policies.filter((p) => p.action === 'deny' || p.action === 'DENY').length
    const allow = policies.filter((p) => p.action === 'allow' || p.action === 'ALLOW').length
    return { total, deny, allow }
  }, [policies])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h3 className="text-lg font-semibold">Active Policies</h3>
          <p className="text-sm text-slate-400">Manage firewall and security policies</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn btn-secondary">Import Pack</button>
          <button onClick={handleOpenCreate} className="btn btn-primary">
            + Create Policy
          </button>
        </div>
      </div>

      {/* Policy Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-sm text-slate-400">Total Policies</p>
          <p className="text-2xl font-bold">{stats.total}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">DENY Rules</p>
          <p className="text-2xl font-bold text-red-400">{stats.deny}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">ALLOW Rules</p>
          <p className="text-2xl font-bold text-emerald-400">{stats.allow}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-slate-400">Total Matches</p>
          <p className="text-2xl font-bold">N/A</p>
        </div>
      </div>

      {/* Policies Table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                <th className="px-6 py-3 text-left font-medium">ID</th>
                <th className="px-6 py-3 text-left font-medium">Name</th>
                <th className="px-6 py-3 text-left font-medium">Action</th>
                <th className="px-6 py-3 text-left font-medium">Source</th>
                <th className="px-6 py-3 text-left font-medium">Destination</th>
                <th className="px-6 py-3 text-left font-medium">Matches</th>
                <th className="px-6 py-3 text-left font-medium">Status</th>
                <th className="px-6 py-3 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={8} className="px-6 py-6 text-sm text-slate-400">
                    Loading policies...
                  </td>
                </tr>
              )}
              {isError && (
                <tr>
                  <td colSpan={8} className="px-6 py-6 text-sm text-red-300">
                    Failed to load policies from the API gateway.
                  </td>
                </tr>
              )}
              {!isLoading && !isError && policies.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-6 py-6 text-center text-sm text-slate-400">
                    No policies available. Create your first policy.
                  </td>
                </tr>
              )}
              {policies.map((policy) => (
                <tr key={policy.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                  <td className="px-6 py-4 text-sm font-mono">{policy.id}</td>
                  <td className="px-6 py-4 text-sm font-medium">{policy.name}</td>
                  <td className="px-6 py-4">
                    <ActionBadge action={String(policy.action).toUpperCase()} />
                  </td>
                  <td className="px-6 py-4 text-sm font-mono text-slate-300">{policy.source_cidr || 'any'}</td>
                  <td className="px-6 py-4 text-sm font-mono text-slate-300">
                    {policy.destination_cidr || 'any'}
                    {policy.port_range ? `:${policy.port_range}` : ''}
                  </td>
                  <td className="px-6 py-4 text-sm">N/A</td>
                  <td className="px-6 py-4">
                    <span className="status-badge status-compliant">{policy.is_active ? 'active' : 'inactive'}</span>
                  </td>
                  <td className="px-6 py-4 space-x-2">
                    <button className="text-blue-400 hover:text-blue-300 text-sm" onClick={() => handleOpenEdit(policy)}>
                      Edit
                    </button>
                    <button className="text-red-400 hover:text-red-300 text-sm" onClick={() => handleDisable(policy)}>
                      Disable
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {message && <p className="text-sm text-slate-300">{message}</p>}

      {showCreateModal && (
        <div className="fixed inset-0 z-40 bg-black/60 flex items-center justify-center p-6">
          <div className="card w-full max-w-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">
                {editingId ? 'Edit Policy' : 'Create Policy'}
              </h3>
              <button className="text-slate-400" onClick={() => setShowCreateModal(false)}>
                X
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label className="block text-sm text-slate-300 mb-1">Name</label>
                <input
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm text-slate-300 mb-1">Description</label>
                <input
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Source CIDR</label>
                <input
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.source_cidr}
                  onChange={(e) => setForm({ ...form, source_cidr: e.target.value })}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Destination CIDR</label>
                <input
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.destination_cidr}
                  onChange={(e) => setForm({ ...form, destination_cidr: e.target.value })}
                  placeholder="0.0.0.0/0"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Protocol</label>
                <select
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.protocol}
                  onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                  <option value="all">All</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Port Range</label>
                <input
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.port_range}
                  onChange={(e) => setForm({ ...form, port_range: e.target.value })}
                  placeholder="80 or 8000-9000"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Action</label>
                <select
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.action}
                  onChange={(e) => setForm({ ...form, action: e.target.value as PolicyAction })}
                >
                  <option value="allow">ALLOW</option>
                  <option value="deny">DENY</option>
                  <option value="log">LOG</option>
                  <option value="rate_limit">RATE LIMIT</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-300 mb-1">Priority</label>
                <input
                  type="number"
                  className="w-full px-3 py-2 bg-slate-900/60 border border-slate-800/80 rounded-lg"
                  value={form.priority}
                  onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })}
                />
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button className="btn btn-secondary" onClick={() => setShowCreateModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleSubmit}>
                {editingId ? 'Update Policy' : 'Create Policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ActionBadge({ action }: { action: string }) {
  const colors: Record<string, string> = {
    DENY: 'bg-red-900/50 text-red-400 border-red-800',
    ALLOW: 'bg-green-900/50 text-green-400 border-green-800',
    RATE_LIMIT: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
    QUARANTINE: 'bg-purple-900/50 text-purple-400 border-purple-800',
    MONITOR: 'bg-blue-900/50 text-blue-400 border-blue-800',
  }
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-medium border ${colors[action] || colors.MONITOR}`}>
      {action}
    </span>
  )
}
