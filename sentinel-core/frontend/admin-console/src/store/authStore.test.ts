import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from './authStore'

vi.mock('../services/api', () => ({
  authApi: {
    login: vi.fn(),
    logout: vi.fn(),
    verifyToken: vi.fn(),
    refreshToken: vi.fn(),
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
      isLoading: false,
    })
  })

  it('clearError clears error state', () => {
    useAuthStore.setState({ error: 'Some error' })
    useAuthStore.getState().clearError()
    expect(useAuthStore.getState().error).toBeNull()
  })

  it('starts in unauthenticated state', () => {
    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(false)
    expect(state.user).toBeNull()
    expect(state.token).toBeNull()
    expect(state.refreshToken).toBeNull()
  })

  it('login stores token and user on success', async () => {
    const { authApi } = await import('../services/api')
    const mockUser = { id: 1, username: 'admin', email: 'a@b.c', role: 'admin', status: 'active', created_at: '', last_login: null }
    vi.mocked(authApi.login).mockResolvedValueOnce({
      data: { access_token: 'jwt-token', refresh_token: 'refresh-token', user: mockUser },
    } as never)

    await useAuthStore.getState().login('admin', 'password')
    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(true)
    expect(state.token).toBe('jwt-token')
    expect(state.refreshToken).toBe('refresh-token')
    expect(state.user?.username).toBe('admin')
  })

  it('logout clears all auth state', async () => {
    useAuthStore.setState({
      isAuthenticated: true,
      token: 'some-token',
      refreshToken: 'some-refresh',
      user: { id: 1, username: 'admin', email: 'a@b.c', role: 'admin', status: 'active', created_at: '', last_login: null },
    })

    const { authApi } = await import('../services/api')
    vi.mocked(authApi.logout).mockResolvedValueOnce({} as never)

    await useAuthStore.getState().logout()
    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(false)
    expect(state.token).toBeNull()
    expect(state.user).toBeNull()
  })
})
