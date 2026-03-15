type RuntimeConfig = {
  apiUrl?: string
  env?: string
  demoAuth?: boolean | string
  appName?: string
  supportEmail?: string
}

const readRuntimeConfig = (): RuntimeConfig => {
  if (typeof window === 'undefined') {
    return {}
  }

  return window.__SENTINEL__ || {}
}

const parseBoolean = (value: unknown, fallback: boolean) => {
  if (typeof value === 'boolean') {
    return value
  }
  if (typeof value === 'string') {
    return ['true', '1', 'yes', 'on'].includes(value.toLowerCase())
  }
  return fallback
}

const normalizeUrl = (value?: string) => {
  if (!value) {
    return ''
  }
  const trimmed = value.replace(/\/+$/, '')
  if (trimmed.endsWith('/api')) {
    return trimmed.slice(0, -4)
  }
  return trimmed
}

const runtime = readRuntimeConfig()

const isLocalhost =
  typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
const demoAuthFallback = Boolean(import.meta.env.DEV) || isLocalhost

export const appConfig = {
  apiBaseUrl: normalizeUrl(import.meta.env.VITE_API_URL || runtime.apiUrl || ''),
  appEnv: import.meta.env.VITE_APP_ENV || runtime.env || import.meta.env.MODE || 'production',
  demoAuth: parseBoolean(import.meta.env.VITE_DEMO_AUTH ?? runtime.demoAuth, demoAuthFallback),
  appName: import.meta.env.VITE_APP_NAME || runtime.appName || 'SENTINEL',
  supportEmail: import.meta.env.VITE_SUPPORT_EMAIL || runtime.supportEmail || 'security@sentinel.local',
}
