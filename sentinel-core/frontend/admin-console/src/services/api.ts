import axios from 'axios'
import { useAuthStore } from '../store/authStore'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout()
    }
    return Promise.reject(error)
  }
)

// API functions
export const threatApi = {
  getThreats: () => api.get('/api/v1/threats'),
  getThreat: (id: string) => api.get(`/api/v1/threats/${id}`),
}

export const policyApi = {
  getPolicies: () => api.get('/api/v1/policies'),
  createPolicy: (data: any) => api.post('/api/v1/policies', data),
  updatePolicy: (id: string, data: any) => api.put(`/api/v1/policies/${id}`, data),
  deletePolicy: (id: string) => api.delete(`/api/v1/policies/${id}`),
}

export const complianceApi = {
  getFrameworks: () => api.get('/api/v1/frameworks'),
  runAssessment: (framework: string, policies: any[]) => 
    api.post('/api/v1/assess', { framework, policies }),
}

export const statsApi = {
  getDashboardStats: () => api.get('/api/v1/statistics'),
  getTrafficStats: () => api.get('/api/v1/traffic'),
}
