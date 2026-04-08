import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'

vi.mock('../config/runtime', () => ({
  appConfig: { apiBaseUrl: 'http://test-api', appEnv: 'test', appName: 'SENTINEL', supportEmail: '' },
}))

const mockToken = { current: null as string | null }

vi.mock('../store/authStore', () => ({
  useAuthStore: {
    getState: () => ({ token: mockToken.current }),
  },
}))

class MockEventSource {
  url: string
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  readyState = 0

  static instances: MockEventSource[] = []

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  close = vi.fn()

  simulateMessage(data: string) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data }))
    }
  }

  simulateError() {
    if (this.onerror) {
      this.onerror(new Event('error'))
    }
  }
}

describe('SSE stream client', () => {
  let createSseClient: typeof import('./stream').createSseClient

  beforeEach(async () => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockToken.current = null

    vi.resetModules()
    const mod = await import('./stream')
    createSseClient = mod.createSseClient
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('creates EventSource with the correct URL (no token)', () => {
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/alerts', onMessage)

    expect(MockEventSource.instances).toHaveLength(1)
    expect(MockEventSource.instances[0].url).toBe('http://test-api/api/v1/stream/alerts')
  })

  it('appends token as query param when authenticated', () => {
    mockToken.current = 'jwt-abc-123'
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/alerts', onMessage)

    expect(MockEventSource.instances[0].url).toBe(
      'http://test-api/api/v1/stream/alerts?token=jwt-abc-123',
    )
  })

  it('URL-encodes special characters in the token', () => {
    mockToken.current = 'token with spaces&special=chars'
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/threats', onMessage)

    expect(MockEventSource.instances[0].url).toContain(
      `?token=${encodeURIComponent('token with spaces&special=chars')}`,
    )
  })

  it('parses JSON messages and calls onMessage with parsed data', () => {
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/alerts', onMessage)

    const instance = MockEventSource.instances[0]
    const payload = { type: 'alert', severity: 'critical', id: 'a-1' }
    instance.simulateMessage(JSON.stringify(payload))

    expect(onMessage).toHaveBeenCalledTimes(1)
    expect(onMessage).toHaveBeenCalledWith(payload)
  })

  it('wraps non-JSON messages as raw payloads', () => {
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/alerts', onMessage)

    const instance = MockEventSource.instances[0]
    instance.simulateMessage('not valid json')

    expect(onMessage).toHaveBeenCalledWith({ type: 'raw', payload: 'not valid json' })
  })

  it('returns the EventSource instance for cleanup', () => {
    const onMessage = vi.fn()
    const es = createSseClient('/api/v1/stream/alerts', onMessage)

    expect(es).toBe(MockEventSource.instances[0])
    es.close()
    expect(MockEventSource.instances[0].close).toHaveBeenCalled()
  })

  it('handles multiple sequential messages', () => {
    const onMessage = vi.fn()
    createSseClient('/api/v1/stream/alerts', onMessage)

    const instance = MockEventSource.instances[0]
    instance.simulateMessage(JSON.stringify({ id: 1 }))
    instance.simulateMessage(JSON.stringify({ id: 2 }))
    instance.simulateMessage(JSON.stringify({ id: 3 }))

    expect(onMessage).toHaveBeenCalledTimes(3)
    expect(onMessage).toHaveBeenNthCalledWith(1, { id: 1 })
    expect(onMessage).toHaveBeenNthCalledWith(2, { id: 2 })
    expect(onMessage).toHaveBeenNthCalledWith(3, { id: 3 })
  })

  it('uses empty base URL when appConfig.apiBaseUrl is empty', async () => {
    vi.resetModules()

    vi.doMock('../config/runtime', () => ({
      appConfig: { apiBaseUrl: '', appEnv: 'test', appName: 'SENTINEL', supportEmail: '' },
    }))

    MockEventSource.instances = []
    const mod = await import('./stream')
    const onMessage = vi.fn()
    mod.createSseClient('/api/v1/stream/alerts', onMessage)

    expect(MockEventSource.instances[0].url).toBe('/api/v1/stream/alerts')
  })
})
