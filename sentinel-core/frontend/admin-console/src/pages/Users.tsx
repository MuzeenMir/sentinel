import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Users as UsersIcon, X } from 'lucide-react'
import { usersApi } from '../services/api'
import type { User } from '../types'

const ROLES = ['admin', 'analyst', 'viewer']
const STATUSES = ['active', 'inactive', 'suspended']

export function Users() {
  const queryClient = useQueryClient()
  const [roleFilter, setRoleFilter] = useState('')
  const [editUser, setEditUser] = useState<User | null>(null)
  const [editRole, setEditRole] = useState('')
  const [editStatus, setEditStatus] = useState('')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['users', roleFilter],
    queryFn: () =>
      usersApi.getUsers(roleFilter ? { role: roleFilter } : undefined).then((r) => r.data),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: number; payload: { role?: string; status?: string } }) =>
      usersApi.updateUser(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setEditUser(null)
    },
  })

  const users: User[] = data?.users ?? data ?? []

  const openEdit = (user: User) => {
    setEditUser(user)
    setEditRole(user.role)
    setEditStatus(user.status)
  }

  const handleUpdate = () => {
    if (!editUser) return
    const updates: { role?: string; status?: string } = {}
    if (editRole !== editUser.role) updates.role = editRole
    if (editStatus !== editUser.status) updates.status = editStatus
    updateMutation.mutate({ id: editUser.id, payload: updates })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <UsersIcon className="h-6 w-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-white">Users</h1>
        </div>
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
                {users.map((user) => (
                  <tr key={user.id} className="hover:bg-slate-800/30">
                    <td className="table-cell font-medium text-white">{user.username}</td>
                    <td className="table-cell text-slate-300">{user.email}</td>
                    <td className="table-cell">
                      <span className="badge bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                        {user.role}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span
                        className={`badge border ${
                          user.status === 'active'
                            ? 'bg-green-500/20 text-green-400 border-green-500/30'
                            : 'bg-slate-500/20 text-slate-400 border-slate-500/30'
                        }`}
                      >
                        {user.status}
                      </span>
                    </td>
                    <td className="table-cell text-xs text-slate-400">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="table-cell text-xs text-slate-400">
                      {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                    </td>
                    <td className="table-cell">
                      <button
                        onClick={() => openEdit(user)}
                        className="text-xs text-cyan-400 hover:text-cyan-300"
                      >
                        Edit
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {editUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="card w-full max-w-md p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Edit User</h3>
              <button
                onClick={() => setEditUser(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Username</label>
                <p className="text-sm font-medium text-white">{editUser.username}</p>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Role</label>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value)}
                  className="select-field w-full"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Status</label>
                <select
                  value={editStatus}
                  onChange={(e) => setEditStatus(e.target.value)}
                  className="select-field w-full"
                >
                  {STATUSES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button onClick={() => setEditUser(null)} className="btn-secondary">
                Cancel
              </button>
              <button onClick={handleUpdate} className="btn-primary">
                Update User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
