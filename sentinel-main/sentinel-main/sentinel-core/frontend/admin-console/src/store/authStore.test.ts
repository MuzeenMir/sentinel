import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from './authStore'

vi.mock('../services/api', () => ({
  authApi: {
    login: vi.fn(),
    logout: vi.fn(),
    verifyToken: vi.fn(),
  },
}))

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({
      isAuthenticated: false,
      user: null,
      token: null,
      refreshToken: null,
      error: null,
    })
    localStorage.clear()
  })

  it('setDemoBypass sets authenticated state with demo user', () => {
    useAuthStore.getState().setDemoBypass()
    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(true)
    expect(state.user?.username).toBe('demo')
    expect(state.token).toBe('demo-bypass')
    expect(state.error).toBeNull()
  })

  it('clearError clears error state', () => {
    useAuthStore.setState({ error: 'Some error' })
    useAuthStore.getState().clearError()
    expect(useAuthStore.getState().error).toBeNull()
  })
})
