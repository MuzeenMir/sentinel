import { create } from 'zustand'
import { authApi } from '../services/api'
import type { User } from '../types'

interface AuthState {
  isAuthenticated: boolean
  user: User | null
  token: string | null
  refreshToken: string | null
  isLoading: boolean
  error: string | null

  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refreshAccessToken: () => Promise<void>
  clearError: () => void
  checkAuth: () => Promise<boolean>
}

export const useAuthStore = create<AuthState>()(
  (set, get) => ({
    isAuthenticated: false,
    user: null,
    token: null,
    refreshToken: null,
    isLoading: false,
    error: null,

    login: async (username: string, password: string) => {
      set({ isLoading: true, error: null })

      try {
        const response = await authApi.login({ username, password })
        const { access_token, refresh_token, user } = response.data

        set({
          isAuthenticated: true,
          user,
          token: access_token,
          refreshToken: refresh_token,
          isLoading: false,
          error: null,
        })
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Login failed'
        set({
          isAuthenticated: false,
          user: null,
          token: null,
          refreshToken: null,
          isLoading: false,
          error: errorMessage,
        })
        throw error
      }
    },

    logout: async () => {
      try {
        if (get().token) {
          await authApi.logout()
        }
      } catch {
        // Ignore errors during logout -- server-side invalidation is best-effort
      } finally {
        set({
          isAuthenticated: false,
          user: null,
          token: null,
          refreshToken: null,
          error: null,
        })
      }
    },

    refreshAccessToken: async () => {
      const { refreshToken } = get()

      if (!refreshToken) {
        throw new Error('No refresh token available')
      }

      try {
        const response = await authApi.refreshToken(refreshToken)
        const newAccessToken = response.data.access_token

        set({ token: newAccessToken })
      } catch {
        await get().logout()
        throw new Error('Session expired')
      }
    },

    clearError: () => set({ error: null }),

    checkAuth: async () => {
      const { token } = get()

      if (!token) {
        return false
      }

      try {
        const response = await authApi.verifyToken()
        set({ user: response.data.user, isAuthenticated: true })
        return true
      } catch {
        await get().logout()
        return false
      }
    },
  })
)
