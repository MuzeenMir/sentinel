import axios from "axios";
import { useAuthStore } from "../store/authStore";
import { appConfig } from "../config/runtime";
import type { LoginResponse, User, PolicyCreateRequest } from "../types";

const API_BASE_URL = appConfig.apiBaseUrl || "";

export const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshPromise: Promise<void> | null = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as typeof error.config & {
      _retry?: boolean;
    };

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        if (!refreshPromise) {
          refreshPromise = useAuthStore
            .getState()
            .refreshAccessToken()
            .finally(() => {
              refreshPromise = null;
            });
        }
        await refreshPromise;

        const newToken = useAuthStore.getState().token;
        if (newToken) {
          originalRequest.headers = originalRequest.headers ?? {};
          originalRequest.headers.Authorization = `Bearer ${newToken}`;
          return api(originalRequest);
        }
      } catch {
        // Refresh failed -- logout was already triggered inside refreshAccessToken.
      }
    }

    return Promise.reject(error);
  },
);

export const authApi = {
  login: (data: { username: string; password: string }) =>
    api.post<LoginResponse>("/api/v1/auth/login", data),
  logout: () => api.post("/api/v1/auth/logout"),
  verifyToken: () => api.post<{ user: User }>("/api/v1/auth/verify"),
  refreshToken: (refreshToken: string) =>
    axios.post<{
      access_token: string;
      token_type: string;
      expires_in: number;
    }>(
      `${API_BASE_URL}/api/v1/auth/refresh`,
      {},
      { headers: { Authorization: `Bearer ${refreshToken}` } },
    ),
};

export const threatApi = {
  getThreats: () => api.get("/api/v1/threats"),
  getThreat: (id: string) => api.get(`/api/v1/threats/${id}`),
};

export const policyApi = {
  getPolicies: () => api.get("/api/v1/policies"),
  createPolicy: (data: PolicyCreateRequest) =>
    api.post("/api/v1/policies", data),
  updatePolicy: (
    id: string,
    data: Partial<PolicyCreateRequest> & Record<string, unknown>,
  ) => api.put(`/api/v1/policies/${id}`, data),
  deletePolicy: (id: string) => api.delete(`/api/v1/policies/${id}`),
};

export type ComplianceFrameworkId =
  | "GDPR"
  | "HIPAA"
  | "PCI-DSS"
  | "NIST"
  | "SOC2";

export const complianceApi = {
  getFrameworks: () => api.get("/api/v1/frameworks"),
  runAssessment: (
    framework: ComplianceFrameworkId,
    policies?: Record<string, unknown>[],
  ) => api.post("/api/v1/assess", { framework, policies: policies ?? [] }),
  getGapAnalysis: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/gap-analysis`),
  getReport: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/report`),
  downloadReport: (framework: ComplianceFrameworkId) =>
    api.get(`/api/v1/frameworks/${framework}/report`, { responseType: "blob" }),
};

export const statsApi = {
  getDashboardStats: () => api.get("/api/v1/statistics"),
  getTrafficStats: () => api.get("/api/v1/traffic"),
};

export const configApi = {
  getConfig: () => api.get<Record<string, unknown>>("/api/v1/config"),
  updateConfig: (data: Record<string, unknown>) =>
    api.put("/api/v1/config", data),
};

export const alertApi = {
  getAlerts: (params?: { status?: string; severity?: string; page?: number }) =>
    api.get("/api/v1/alerts", { params }),
  getAlert: (id: string) => api.get(`/api/v1/alerts/${id}`),
  acknowledge: (id: string) => api.post(`/api/v1/alerts/${id}/acknowledge`),
  resolve: (id: string) => api.post(`/api/v1/alerts/${id}/resolve`),
  ignore: (id: string) =>
    api.put(`/api/v1/alerts/${id}`, { status: "ignored" }),
  getStats: () => api.get("/api/v1/alerts/stats"),
};

export const hardeningApi = {
  getScan: () => api.get("/api/v1/hardening/scan"),
  triggerScan: () => api.post("/api/v1/hardening/scan"),
  getPosture: () => api.get("/api/v1/hardening/posture"),
  getRemediations: () => api.get("/api/v1/hardening/remediations"),
  remediate: (checkId: string) =>
    api.post(`/api/v1/hardening/remediate/${checkId}`),
};

export const hidsApi = {
  getEvents: (params?: {
    event_type?: string;
    page?: number;
    per_page?: number;
  }) => api.get("/api/v1/hids/events", { params }),
  getAlerts: () => api.get("/api/v1/hids/alerts"),
  getStatus: () => api.get("/api/v1/hids/status"),
};

export const usersApi = {
  getUsers: (params?: { page?: number; role?: string }) =>
    api.get("/api/v1/admin/users", { params }),
  updateUser: (id: number, data: { role?: string; status?: string }) =>
    api.put(`/api/v1/admin/users/${id}`, data),
};

export const auditApi = {
  getEvents: (params?: {
    category?: string;
    actor?: string;
    start_time?: number;
    end_time?: number;
    limit?: number;
    offset?: number;
  }) => api.get("/api/v1/audit/events", { params }),
  getStats: () => api.get("/api/v1/audit/stats"),
  getCategories: () =>
    api.get<{ categories: string[] }>("/api/v1/audit/categories"),
  verifyIntegrity: (records: Record<string, unknown>[]) =>
    api.post("/api/v1/audit/verify", { records }),
};

export const tenantApi = {
  list: () => api.get("/api/v1/tenants"),
  get: (id: number) => api.get(`/api/v1/tenants/${id}`),
  create: (data: {
    name: string;
    plan: string;
    max_users?: number;
    max_agents?: number;
  }) => api.post("/api/v1/tenants", data),
  update: (
    id: number,
    data: Partial<{
      name: string;
      plan: string;
      status: string;
      max_users: number;
      max_agents: number;
    }>,
  ) => api.put(`/api/v1/tenants/${id}`, data),
  deactivate: (id: number) => api.delete(`/api/v1/tenants/${id}`),
};

export const mfaApi = {
  status: () => api.get("/api/v1/auth/mfa/status"),
  enroll: () => api.post("/api/v1/auth/mfa/enroll"),
  verify: (code: string) => api.post("/api/v1/auth/mfa/verify", { code }),
  disable: (code: string) => api.post("/api/v1/auth/mfa/disable", { code }),
  generateBackupCodes: () => api.post("/api/v1/auth/mfa/backup-codes"),
};

export const siemApi = {
  list: () => api.get("/api/v1/integrations"),
  create: (data: Record<string, unknown>) =>
    api.post("/api/v1/integrations", data),
  test: (data: Record<string, unknown>) =>
    api.post("/api/v1/integrations/test", data),
};
