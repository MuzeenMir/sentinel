import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  isAuthenticated: boolean
  user: { username: string } | null
  token: string | null
  login: (username: string, token: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isAuthenticated: false,
      user: null,
      token: null,
      login: (username, token) => set({
        isAuthenticated: true,
        user: { username },
        token,
      }),
      logout: () => set({
        isAuthenticated: false,
        user: null,
        token: null,
      }),
    }),
    { name: 'sentinel-auth' }
  )
)
