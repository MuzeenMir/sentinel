import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { authApi } from '../services/api'
import type { User } from '../types'

export const DEMO_BYPASS_TOKEN = 'demo-bypass'

const placeholderDemoUser: User = {
  id: 0,
  username: 'demo',
  email: 'demo@sentinel.local',
  role: 'admin',
  status: 'active',
  created_at: new Date().toISOString(),
  last_login: null,
}

interface AuthState {
  isAuthenticated: boolean
  user: User | null
  token: string | null
  refreshToken: string | null
  isLoading: boolean
  error: string | null
  
  // Actions
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refreshAccessToken: () => Promise<void>
  clearError: () => void
  checkAuth: () => Promise<boolean>
  setDemoBypass: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
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
          
          // Store tokens in localStorage for API interceptor
          localStorage.setItem('sentinel-token', access_token)
          localStorage.setItem('sentinel-refresh-token', refresh_token)
          
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
          // Call logout API to invalidate token
          if (get().token) {
            await authApi.logout()
          }
        } catch {
          // Ignore errors during logout
        } finally {
          // Clear local state and storage
          localStorage.removeItem('sentinel-token')
          localStorage.removeItem('sentinel-refresh-token')
          
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
          const response = await authApi.verifyToken()
          const newToken = response.data.user ? get().token : null
          
          if (newToken) {
            localStorage.setItem('sentinel-token', newToken)
            set({ token: newToken })
          }
        } catch {
          // Refresh failed - logout
          await get().logout()
          throw new Error('Session expired')
        }
      },

      clearError: () => set({ error: null }),

      setDemoBypass: () => {
        set({
          isAuthenticated: true,
          user: placeholderDemoUser,
          token: DEMO_BYPASS_TOKEN,
          refreshToken: null,
          isLoading: false,
          error: null,
        })
      },

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
    }),
    {
      name: 'sentinel-auth',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        isAuthenticated: state.isAuthenticated,
        user: state.user,
        token: state.token,
        refreshToken: state.refreshToken,
      }),
    }
  )
)
