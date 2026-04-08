import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Building2, Plus, Trash2, Edit2, X, Check } from 'lucide-react'
import { tenantApi } from '../services/api'
import type { Tenant } from '../types'

const PLANS = ['free', 'starter', 'professional', 'enterprise']

function statusBadge(status: string) {
  const cls =
    status === 'active'
      ? 'bg-green-500/20 text-green-400 border-green-500/30'
      : status === 'suspended'
      ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      : 'bg-slate-600/30 text-slate-400 border-slate-600/50'
  return (
    <span className={`badge border ${cls}`}>{status}</span>
  )
}

interface TenantFormData {
  name: string
  plan: string
  max_users: string
  max_agents: string
}

const emptyForm: TenantFormData = { name: '', plan: 'starter', max_users: '50', max_agents: '10' }

export function Tenants() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<TenantFormData>(emptyForm)
  const [editForm, setEditForm] = useState<TenantFormData>(emptyForm)
  const [error, setError] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => tenantApi.list().then((r) => r.data),
  })

  const tenants: Tenant[] = data?.tenants ?? []

  const createMutation = useMutation({
    mutationFn: (d: TenantFormData) =>
      tenantApi.create({
        name: d.name,
        plan: d.plan,
        max_users: parseInt(d.max_users) || 50,
        max_agents: parseInt(d.max_agents) || 10,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenants'] })
      setShowCreate(false)
      setForm(emptyForm)
      setError('')
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Failed to create tenant')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, d }: { id: number; d: TenantFormData }) =>
      tenantApi.update(id, {
        name: d.name,
        plan: d.plan,
        max_users: parseInt(d.max_users) || 50,
        max_agents: parseInt(d.max_agents) || 10,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenants'] })
      setEditId(null)
      setError('')
    },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error
      setError(msg ?? 'Failed to update tenant')
    },
  })

  const deactivateMutation = useMutation({
    mutationFn: (id: number) => tenantApi.deactivate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tenants'] }),
  })

  const startEdit = (t: Tenant) => {
    setEditId(t.id)
    setEditForm({
      name: t.name,
      plan: t.plan,
      max_users: String(t.max_users),
      max_agents: String(t.max_agents),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Building2 className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Tenant Management</h1>
        </div>
        <button
          onClick={() => { setShowCreate(true); setError('') }}
          className="btn-primary gap-2"
        >
          <Plus className="h-4 w-4" /> New Tenant
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {showCreate && (
        <div className="card p-6 space-y-4">
          <h2 className="text-lg font-semibold text-white">Create Tenant</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Acme Corp"
                className="input-field"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Plan</label>
              <select
                value={form.plan}
                onChange={(e) => setForm({ ...form, plan: e.target.value })}
                className="select-field w-full"
              >
                {PLANS.map((p) => (
                  <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Max Users</label>
              <input
                type="number"
                value={form.max_users}
                onChange={(e) => setForm({ ...form, max_users: e.target.value })}
                className="input-field"
                min="1"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Max Agents</label>
              <input
                type="number"
                value={form.max_agents}
                onChange={(e) => setForm({ ...form, max_agents: e.target.value })}
                className="input-field"
                min="1"
              />
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => createMutation.mutate(form)}
              disabled={!form.name || createMutation.isPending}
              className="btn-primary gap-2"
            >
              <Check className="h-4 w-4" /> Create
            </button>
            <button onClick={() => { setShowCreate(false); setError('') }} className="btn-secondary gap-2">
              <X className="h-4 w-4" /> Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="card p-12 text-center">
          <p className="text-slate-400">Loading tenants…</p>
        </div>
      ) : isError ? (
        <div className="card p-12 text-center">
          <p className="text-red-400">Failed to load tenants.</p>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/50">
                  <th className="table-header">Name</th>
                  <th className="table-header">Plan</th>
                  <th className="table-header">Status</th>
                  <th className="table-header">Max Users</th>
                  <th className="table-header">Max Agents</th>
                  <th className="table-header">Created</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {tenants.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="table-cell text-center text-slate-400">
                      No tenants found.
                    </td>
                  </tr>
                ) : (
                  tenants.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-800/30">
                      {editId === t.id ? (
                        <>
                          <td className="table-cell">
                            <input
                              value={editForm.name}
                              onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                              className="input-field text-sm py-1"
                            />
                          </td>
                          <td className="table-cell">
                            <select
                              value={editForm.plan}
                              onChange={(e) => setEditForm({ ...editForm, plan: e.target.value })}
                              className="select-field text-sm py-1"
                            >
                              {PLANS.map((p) => <option key={p} value={p}>{p}</option>)}
                            </select>
                          </td>
                          <td className="table-cell">{statusBadge(t.status)}</td>
                          <td className="table-cell">
                            <input
                              type="number"
                              value={editForm.max_users}
                              onChange={(e) => setEditForm({ ...editForm, max_users: e.target.value })}
                              className="input-field text-sm py-1 w-20"
                            />
                          </td>
                          <td className="table-cell">
                            <input
                              type="number"
                              value={editForm.max_agents}
                              onChange={(e) => setEditForm({ ...editForm, max_agents: e.target.value })}
                              className="input-field text-sm py-1 w-20"
                            />
                          </td>
                          <td className="table-cell text-slate-400 text-xs">
                            {new Date(t.created_at).toLocaleDateString()}
                          </td>
                          <td className="table-cell">
                            <div className="flex gap-2">
                              <button
                                onClick={() => updateMutation.mutate({ id: t.id, d: editForm })}
                                disabled={updateMutation.isPending}
                                className="text-green-400 hover:text-green-300"
                                title="Save"
                              >
                                <Check className="h-4 w-4" />
                              </button>
                              <button
                                onClick={() => setEditId(null)}
                                className="text-slate-400 hover:text-slate-300"
                                title="Cancel"
                              >
                                <X className="h-4 w-4" />
                              </button>
                            </div>
                          </td>
                        </>
                      ) : (
                        <>
                          <td className="table-cell font-medium text-white">{t.name}</td>
                          <td className="table-cell">
                            <span className="badge bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 capitalize">
                              {t.plan}
                            </span>
                          </td>
                          <td className="table-cell">{statusBadge(t.status)}</td>
                          <td className="table-cell text-slate-300">{t.max_users}</td>
                          <td className="table-cell text-slate-300">{t.max_agents}</td>
                          <td className="table-cell text-slate-400 text-xs">
                            {new Date(t.created_at).toLocaleDateString()}
                          </td>
                          <td className="table-cell">
                            <div className="flex gap-2">
                              <button
                                onClick={() => startEdit(t)}
                                className="text-cyan-400 hover:text-cyan-300"
                                title="Edit"
                              >
                                <Edit2 className="h-4 w-4" />
                              </button>
                              <button
                                onClick={() => {
                                  if (confirm(`Deactivate tenant "${t.name}"?`))
                                    deactivateMutation.mutate(t.id)
                                }}
                                className="text-red-400 hover:text-red-300"
                                title="Deactivate"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </div>
                          </td>
                        </>
                      )}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
