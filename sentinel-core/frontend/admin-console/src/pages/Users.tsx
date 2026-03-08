import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { usersApi } from '../services/api'
import { useAuthStore } from '../store/authStore'
import type { User, UserRole, UserStatus } from '../types'

const ROLE_LABELS: Record<string, string> = {
  admin: 'Admin',
  operator: 'Operator',
  security_analyst: 'Security Analyst',
  auditor: 'Auditor',
  viewer: 'Viewer',
}

const STATUS_COLORS: Record<UserStatus, string> = {
  active: 'text-green-400',
  inactive: 'text-slate-400',
  suspended: 'text-red-400',
}

export function Users() {
  const currentUser = useAuthStore((s) => s.user)
  const isAdmin = currentUser?.role === 'admin'
  const queryClient = useQueryClient()

  const [editingId, setEditingId] = useState<number | null>(null)
  const [editRole, setEditRole] = useState<UserRole>('viewer')
  const [editStatus, setEditStatus] = useState<UserStatus>('active')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const res = await usersApi.getUsers()
      return res.data
    },
    enabled: isAdmin,
  })

  const updateMut = useMutation({
    mutationFn: ({ id, updates }: { id: number; updates: { role?: string; status?: string } }) =>
      usersApi.updateUser(id, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setEditingId(null)
    },
  })

  const users: User[] = (data as { users?: User[] })?.users ?? []

  if (!isAdmin) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <p className="text-slate-400">You need Admin role to access user management.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Users &amp; RBAC</h1>
        <p className="text-sm text-slate-400 mt-1">
          Manage user accounts and role-based access control
        </p>
      </div>

      {/* Role reference */}
      <div className="card p-4">
        <h3 className="text-sm font-semibold mb-3">Role Permissions</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          {Object.entries(ROLE_LABELS).map(([role, label]) => (
            <div key={role} className="bg-slate-900/60 rounded p-2">
              <p className="font-medium text-slate-200">{label}</p>
              <p className="text-slate-500 mt-1">
                {role === 'admin' && 'Full access'}
                {role === 'operator' && 'Manage policies & alerts'}
                {role === 'security_analyst' && 'View & investigate threats'}
                {role === 'auditor' && 'Read-only + compliance reports'}
                {role === 'viewer' && 'Read-only dashboard'}
              </p>
            </div>
          ))}
        </div>
      </div>

      {isLoading && <div className="card p-8 text-center text-slate-400 text-sm">Loading users…</div>}
      {isError && (
        <div className="card p-8 text-center text-red-400 text-sm">
          Failed to load users. Ensure auth-service is running.
        </div>
      )}

      {!isLoading && !isError && (
        <div className="card">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800/80 text-xs uppercase text-slate-500">
                  <th className="px-6 py-3 text-left font-medium">User</th>
                  <th className="px-6 py-3 text-left font-medium">Email</th>
                  <th className="px-6 py-3 text-left font-medium">Role</th>
                  <th className="px-6 py-3 text-left font-medium">Status</th>
                  <th className="px-6 py-3 text-left font-medium">Last Login</th>
                  <th className="px-6 py-3 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-600/30 flex items-center justify-center text-xs font-bold text-blue-300">
                          {user.username.slice(0, 2).toUpperCase()}
                        </div>
                        <span className="text-sm font-medium">{user.username}</span>
                        {user.id === currentUser?.id && (
                          <span className="text-xs text-blue-400">(you)</span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-400">{user.email}</td>
                    <td className="px-6 py-4">
                      {editingId === user.id ? (
                        <select
                          value={editRole}
                          onChange={(e) => setEditRole(e.target.value as UserRole)}
                          className="input text-xs"
                        >
                          {Object.entries(ROLE_LABELS).map(([role, label]) => (
                            <option key={role} value={role}>{label}</option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-xs px-2 py-1 rounded-full bg-blue-500/20 text-blue-300">
                          {ROLE_LABELS[user.role] ?? user.role}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {editingId === user.id ? (
                        <select
                          value={editStatus}
                          onChange={(e) => setEditStatus(e.target.value as UserStatus)}
                          className="input text-xs"
                        >
                          <option value="active">Active</option>
                          <option value="inactive">Inactive</option>
                          <option value="suspended">Suspended</option>
                        </select>
                      ) : (
                        <span className={clsx('text-xs font-medium', STATUS_COLORS[user.status])}>
                          {user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400">
                      {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-6 py-4">
                      {user.id === currentUser?.id ? (
                        <span className="text-xs text-slate-500">—</span>
                      ) : editingId === user.id ? (
                        <div className="flex gap-2">
                          <button
                            disabled={updateMut.isPending}
                            onClick={() =>
                              updateMut.mutate({ id: user.id, updates: { role: editRole, status: editStatus } })
                            }
                            className="text-xs text-green-400 hover:text-green-300 disabled:opacity-50"
                          >
                            Save
                          </button>
                          <button
                            onClick={() => setEditingId(null)}
                            className="text-xs text-slate-400 hover:text-slate-300"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => {
                            setEditingId(user.id)
                            setEditRole(user.role)
                            setEditStatus(user.status)
                          }}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          Edit
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {users.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-sm text-slate-400">
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
