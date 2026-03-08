import axios from 'axios'
import { useAuthStore, DEMO_BYPASS_TOKEN } from '../store/authStore'
import { appConfig } from '../config/runtime'
import type { LoginResponse, User, PolicyCreateRequest } from '../types'

const API_BASE_URL = appConfig.apiBaseUrl || ''

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor — attach Bearer token to every outgoing request.
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token && token !== DEMO_BYPASS_TOKEN) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Track whether a token refresh is already in-flight to avoid parallel attempts.
let refreshPromise: Promise<void> | null = null

// Response interceptor — on 401, attempt a single token refresh then retry.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as typeof error.config & { _retry?: boolean }
    const token = useAuthStore.getState().token

    // Skip refresh for demo sessions or if this request already retried once.
    if (
      error.response?.status === 401 &&
      token !== DEMO_BYPASS_TOKEN &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true

      try {
        if (!refreshPromise) {
          refreshPromise = useAuthStore.getState().refreshAccessToken().finally(() => {
            refreshPromise = null
          })
        }
        await refreshPromise

        // Retry the original request with the new access token.
        const newToken = useAuthStore.getState().token
        if (newToken) {
          originalRequest.headers = originalRequest.headers ?? {}
          originalRequest.headers.Authorization = `Bearer ${newToken}`
          return api(originalRequest)
        }
      } catch {
        // Refresh failed — session is gone; logout was already called inside refreshAccessToken.
      }
    }

    return Promise.reject(error)
  }
)

// API functions
export const authApi = {
  login: (data: { username: string; password: string }) =>
    api.post<LoginResponse>('/api/v1/auth/login', data),
  logout: () => api.post('/api/v1/auth/logout'),
  verifyToken: () => api.post<{ user: User }>('/api/v1/auth/verify'),
  refreshToken: (refreshToken: string) =>
    axios.post<{ access_token: string; token_type: string; expires_in: number }>(
      `${API_BASE_URL}/api/v1/auth/refresh`,
      {},
      { headers: { Authorization: `Bearer ${refreshToken}` } }
    ),
}

export const threatApi = {
  getThreats: () => api.get('/api/v1/threats'),
  getThreat: (id: string) => api.get(`/api/v1/threats/${id}`),
}

export const policyApi = {
  getPolicies: () => api.get('/api/v1/policies'),
  createPolicy: (data: PolicyCreateRequest) => api.post('/api/v1/policies', data),
  updatePolicy: (id: string, data: Partial<PolicyCreateRequest> & Record<string, unknown>) =>
    api.put(`/api/v1/policies/${id}`, data),
  deletePolicy: (id: string) => api.delete(`/api/v1/policies/${id}`),
}

export type ComplianceFrameworkId = 'GDPR' | 'HIPAA' | 'PCI-DSS' | 'NIST' | 'SOC2'

export const complianceApi = {
  getFrameworks: () => api.get('/api/v1/frameworks'),
  runAssessment: (framework: ComplianceFrameworkId, policies?: Record<string, unknown>[]) =>
    api.post('/api/v1/assess', { framework, policies: policies ?? [] }),
  getGapAnalysis: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/gap-analysis`),
  getReport: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/report`),
  downloadReport: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/report`, { responseType: 'blob' }),
}

export const statsApi = {
  getDashboardStats: () => api.get('/api/v1/statistics'),
  getTrafficStats: () => api.get('/api/v1/traffic'),
}

export const configApi = {
  getConfig: () => api.get<Record<string, unknown>>('/api/v1/config'),
  updateConfig: (data: Record<string, unknown>) => api.put('/api/v1/config', data),
}

export const alertApi = {
  getAlerts: (params?: { status?: string; severity?: string; page?: number }) =>
    api.get('/api/v1/alerts', { params }),
  getAlert: (id: string) => api.get(`/api/v1/alerts/${id}`),
  acknowledge: (id: string) => api.put(`/api/v1/alerts/${id}/acknowledge`),
  resolve: (id: string) => api.put(`/api/v1/alerts/${id}/resolve`),
  ignore: (id: string) => api.put(`/api/v1/alerts/${id}/ignore`),
  getStats: () => api.get('/api/v1/alerts/stats'),
}

export const hardeningApi = {
  getScan: () => api.get('/api/v1/hardening/scan'),
  triggerScan: () => api.post('/api/v1/hardening/scan'),
  getPosture: () => api.get('/api/v1/hardening/posture'),
  getRemediations: () => api.get('/api/v1/hardening/remediations'),
  remediate: (checkId: string) => api.post(`/api/v1/hardening/remediate/${checkId}`),
}

export const hidsApi = {
  getEvents: (params?: { event_type?: string; page?: number; per_page?: number }) =>
    api.get('/api/v1/hids/events', { params }),
  getAlerts: () => api.get('/api/v1/hids/alerts'),
  getStatus: () => api.get('/api/v1/hids/status'),
}

export const usersApi = {
  getUsers: (params?: { page?: number; role?: string }) =>
    api.get('/api/v1/admin/users', { params }),
  updateUser: (id: number, data: { role?: string; status?: string }) =>
    api.put(`/api/v1/admin/users/${id}`, data),
}

export const auditApi = {
  getEvents: (params?: { page?: number; event_type?: string; from?: string; to?: string }) =>
    api.get('/api/v1/audit/events', { params }),
}
