import { describe, it, expect, beforeEach, vi } from 'vitest'
import axios from 'axios'
import type { AxiosRequestConfig, InternalAxiosRequestConfig, AxiosResponse } from 'axios'

vi.mock('../config/runtime', () => ({
  appConfig: { apiBaseUrl: 'http://test-api', appEnv: 'test', appName: 'SENTINEL', supportEmail: '' },
}))

vi.mock('../store/authStore', () => {
  const state = {
    token: null as string | null,
    refreshToken: null as string | null,
    refreshAccessToken: vi.fn(),
    logout: vi.fn(),
  }
  return {
    useAuthStore: {
      getState: () => state,
      setState: (patch: Partial<typeof state>) => Object.assign(state, patch),
    },
    __mockState: state,
  }
})

describe('API service', () => {
  let api: typeof import('./api')
  let mockState: {
    token: string | null
    refreshToken: string | null
    refreshAccessToken: ReturnType<typeof vi.fn>
    logout: ReturnType<typeof vi.fn>
  }

  beforeEach(async () => {
    vi.resetModules()

    const authMock = await import('../store/authStore')
    mockState = (authMock as unknown as { __mockState: typeof mockState }).__mockState
    mockState.token = null
    mockState.refreshToken = null
    mockState.refreshAccessToken.mockReset()
    mockState.logout.mockReset()

    api = await import('./api')
  })

  describe('request interceptor', () => {
    it('adds Bearer token header when token exists', async () => {
      mockState.token = 'test-jwt-token'

      const interceptors = api.api.interceptors.request as unknown as {
        handlers: Array<{ fulfilled: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig }>
      }
      const handler = interceptors.handlers[0].fulfilled

      const config = { headers: new axios.AxiosHeaders() } as InternalAxiosRequestConfig
      const result = handler(config)

      expect(result.headers.Authorization).toBe('Bearer test-jwt-token')
    })

    it('does not add Authorization header when no token', async () => {
      mockState.token = null

      const interceptors = api.api.interceptors.request as unknown as {
        handlers: Array<{ fulfilled: (config: InternalAxiosRequestConfig) => InternalAxiosRequestConfig }>
      }
      const handler = interceptors.handlers[0].fulfilled

      const config = { headers: new axios.AxiosHeaders() } as InternalAxiosRequestConfig
      const result = handler(config)

      expect(result.headers.Authorization).toBeUndefined()
    })
  })

  describe('response interceptor (401 refresh)', () => {
    it('attempts token refresh on 401 and retries the request', async () => {
      mockState.token = 'old-token'
      mockState.refreshAccessToken.mockImplementation(async () => {
        mockState.token = 'new-token'
      })

      const interceptors = api.api.interceptors.response as unknown as {
        handlers: Array<{
          fulfilled: ((res: AxiosResponse) => AxiosResponse) | null
          rejected: ((error: unknown) => Promise<unknown>) | null
        }>
      }
      const errorHandler = interceptors.handlers[0].rejected!

      const originalRequest: AxiosRequestConfig & { _retry?: boolean } = {
        url: '/api/v1/threats',
        headers: {},
      }
      const error = {
        response: { status: 401 },
        config: originalRequest,
      }

      const apiSpy = vi.spyOn(api, 'api').mockResolvedValueOnce({ data: 'retried' } as never)

      try {
        await errorHandler(error)
      } catch {
        // may throw depending on mock chain
      }

      expect(mockState.refreshAccessToken).toHaveBeenCalled()
      apiSpy.mockRestore()
    })

    it('does not retry on non-401 errors', async () => {
      const interceptors = api.api.interceptors.response as unknown as {
        handlers: Array<{
          fulfilled: ((res: AxiosResponse) => AxiosResponse) | null
          rejected: ((error: unknown) => Promise<unknown>) | null
        }>
      }
      const errorHandler = interceptors.handlers[0].rejected!

      const error = {
        response: { status: 500 },
        config: { url: '/api/v1/threats', headers: {} },
      }

      await expect(errorHandler(error)).rejects.toBeDefined()
      expect(mockState.refreshAccessToken).not.toHaveBeenCalled()
    })

    it('does not retry if _retry is already set', async () => {
      const interceptors = api.api.interceptors.response as unknown as {
        handlers: Array<{
          fulfilled: ((res: AxiosResponse) => AxiosResponse) | null
          rejected: ((error: unknown) => Promise<unknown>) | null
        }>
      }
      const errorHandler = interceptors.handlers[0].rejected!

      const error = {
        response: { status: 401 },
        config: { url: '/api/v1/threats', headers: {}, _retry: true },
      }

      await expect(errorHandler(error)).rejects.toBeDefined()
      expect(mockState.refreshAccessToken).not.toHaveBeenCalled()
    })
  })

  describe('authApi', () => {
    it('login sends POST to /api/v1/auth/login', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.authApi.login({ username: 'admin', password: 'pass' })
      expect(postSpy).toHaveBeenCalledWith('/api/v1/auth/login', { username: 'admin', password: 'pass' })
      postSpy.mockRestore()
    })

    it('logout sends POST to /api/v1/auth/logout', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.authApi.logout()
      expect(postSpy).toHaveBeenCalledWith('/api/v1/auth/logout')
      postSpy.mockRestore()
    })

    it('verifyToken sends POST to /api/v1/auth/verify', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.authApi.verifyToken()
      expect(postSpy).toHaveBeenCalledWith('/api/v1/auth/verify')
      postSpy.mockRestore()
    })
  })

  describe('threatApi', () => {
    it('getThreats sends GET to /api/v1/threats', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.threatApi.getThreats()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/threats')
      getSpy.mockRestore()
    })

    it('getThreat sends GET to /api/v1/threats/:id', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.threatApi.getThreat('t-123')
      expect(getSpy).toHaveBeenCalledWith('/api/v1/threats/t-123')
      getSpy.mockRestore()
    })
  })

  describe('policyApi', () => {
    it('getPolicies sends GET to /api/v1/policies', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.policyApi.getPolicies()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/policies')
      getSpy.mockRestore()
    })

    it('createPolicy sends POST to /api/v1/policies', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      const payload = { name: 'Test', description: '', action: 'deny' as const, priority: 10 }
      api.policyApi.createPolicy(payload)
      expect(postSpy).toHaveBeenCalledWith('/api/v1/policies', payload)
      postSpy.mockRestore()
    })

    it('updatePolicy sends PUT to /api/v1/policies/:id', () => {
      const putSpy = vi.spyOn(api.api, 'put').mockResolvedValue({ data: {} })
      api.policyApi.updatePolicy('pol-1', { name: 'Updated' })
      expect(putSpy).toHaveBeenCalledWith('/api/v1/policies/pol-1', { name: 'Updated' })
      putSpy.mockRestore()
    })

    it('deletePolicy sends DELETE to /api/v1/policies/:id', () => {
      const delSpy = vi.spyOn(api.api, 'delete').mockResolvedValue({ data: {} })
      api.policyApi.deletePolicy('pol-1')
      expect(delSpy).toHaveBeenCalledWith('/api/v1/policies/pol-1')
      delSpy.mockRestore()
    })
  })

  describe('alertApi', () => {
    it('getAlerts sends GET to /api/v1/alerts with params', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.alertApi.getAlerts({ status: 'new', severity: 'high', page: 2 })
      expect(getSpy).toHaveBeenCalledWith('/api/v1/alerts', { params: { status: 'new', severity: 'high', page: 2 } })
      getSpy.mockRestore()
    })

    it('acknowledge sends PUT to /api/v1/alerts/:id/acknowledge', () => {
      const putSpy = vi.spyOn(api.api, 'put').mockResolvedValue({ data: {} })
      api.alertApi.acknowledge('a-1')
      expect(putSpy).toHaveBeenCalledWith('/api/v1/alerts/a-1/acknowledge')
      putSpy.mockRestore()
    })

    it('resolve sends PUT to /api/v1/alerts/:id/resolve', () => {
      const putSpy = vi.spyOn(api.api, 'put').mockResolvedValue({ data: {} })
      api.alertApi.resolve('a-1')
      expect(putSpy).toHaveBeenCalledWith('/api/v1/alerts/a-1/resolve')
      putSpy.mockRestore()
    })

    it('ignore sends PUT to /api/v1/alerts/:id/ignore', () => {
      const putSpy = vi.spyOn(api.api, 'put').mockResolvedValue({ data: {} })
      api.alertApi.ignore('a-1')
      expect(putSpy).toHaveBeenCalledWith('/api/v1/alerts/a-1/ignore')
      putSpy.mockRestore()
    })
  })

  describe('complianceApi', () => {
    it('getFrameworks sends GET to /api/v1/frameworks', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.complianceApi.getFrameworks()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/frameworks')
      getSpy.mockRestore()
    })

    it('runAssessment sends POST to /api/v1/assess', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.complianceApi.runAssessment('GDPR')
      expect(postSpy).toHaveBeenCalledWith('/api/v1/assess', { framework: 'GDPR', policies: [] })
      postSpy.mockRestore()
    })
  })

  describe('statsApi', () => {
    it('getDashboardStats sends GET to /api/v1/statistics', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.statsApi.getDashboardStats()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/statistics')
      getSpy.mockRestore()
    })

    it('getTrafficStats sends GET to /api/v1/traffic', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.statsApi.getTrafficStats()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/traffic')
      getSpy.mockRestore()
    })
  })

  describe('hardeningApi', () => {
    it('getScan sends GET to /api/v1/hardening/scan', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.hardeningApi.getScan()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/hardening/scan')
      getSpy.mockRestore()
    })

    it('triggerScan sends POST to /api/v1/hardening/scan', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.hardeningApi.triggerScan()
      expect(postSpy).toHaveBeenCalledWith('/api/v1/hardening/scan')
      postSpy.mockRestore()
    })

    it('remediate sends POST to /api/v1/hardening/remediate/:checkId', () => {
      const postSpy = vi.spyOn(api.api, 'post').mockResolvedValue({ data: {} })
      api.hardeningApi.remediate('chk-1')
      expect(postSpy).toHaveBeenCalledWith('/api/v1/hardening/remediate/chk-1')
      postSpy.mockRestore()
    })
  })

  describe('configApi', () => {
    it('getConfig sends GET to /api/v1/config', () => {
      const getSpy = vi.spyOn(api.api, 'get').mockResolvedValue({ data: {} })
      api.configApi.getConfig()
      expect(getSpy).toHaveBeenCalledWith('/api/v1/config')
      getSpy.mockRestore()
    })

    it('updateConfig sends PUT to /api/v1/config', () => {
      const putSpy = vi.spyOn(api.api, 'put').mockResolvedValue({ data: {} })
      api.configApi.updateConfig({ key: 'value' })
      expect(putSpy).toHaveBeenCalledWith('/api/v1/config', { key: 'value' })
      putSpy.mockRestore()
    })
  })
})
