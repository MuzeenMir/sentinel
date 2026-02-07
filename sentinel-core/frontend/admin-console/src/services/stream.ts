import { appConfig } from '../config/runtime'
import { useAuthStore, DEMO_BYPASS_TOKEN } from '../store/authStore'

export type StreamMessage = {
  type?: string
  timestamp?: number
  [key: string]: unknown
}

export const createSseClient = (
  path: string,
  onMessage: (data: StreamMessage) => void
) => {
  const base = appConfig.apiBaseUrl || ''
  const token = useAuthStore.getState().token
  const tokenParam = token && token !== DEMO_BYPASS_TOKEN ? `?token=${encodeURIComponent(token)}` : ''
  const url = `${base}${path}${tokenParam}`
  const eventSource = new EventSource(url)

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data)
    } catch {
      onMessage({ type: 'raw', payload: event.data })
    }
  }

  return eventSource
}
