import { Page, expect } from '@playwright/test'

const demoUser = {
  id: 1,
  username: 'demo',
  email: 'demo@sentinel.local',
  role: 'admin',
  status: 'active',
  created_at: '2026-01-01T00:00:00Z',
  last_login: null,
}

const loginResponseBody = {
  access_token: 'test-access-token',
  refresh_token: 'test-refresh-token',
  user: demoUser,
}

const STATS_JSON = {
  totalThreats: 12,
  blockedThreats: 10,
  activePolicies: 4,
  complianceScore: 92,
}

const TRAFFIC_JSON = [
  { time: '00:00', inbound: 1000, outbound: 500, threats: 1 },
  { time: '01:00', inbound: 1200, outbound: 600, threats: 2 },
]

export const mockAuthRoutes = async (page: Page) => {
  await page.route(/\/api\/v1\/auth\/(login|verify)/, async (route) => {
    const url = route.request().url()
    if (url.includes('login')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(loginResponseBody) })
    } else {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ user: demoUser }) })
    }
  })
}

export const mockDashboardRoutes = async (page: Page) => {
  await page.route(/\/api\/v1\/(statistics|traffic)/, async (route) => {
    const url = route.request().url()
    if (url.includes('statistics')) {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(STATS_JSON) })
    } else {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(TRAFFIC_JSON) })
    }
  })
}

export const mockThreatRoutes = async (page: Page) => {
  await page.route('**/api/v1/threats', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        threats: [
          {
            id: 'TH-1',
            type: 'DDoS Attack',
            severity: 'critical',
            source_ip: '192.0.2.10',
            dest_ip: '198.51.100.20',
            status: 'new',
            timestamp: '2026-02-02T00:00:00Z',
          },
        ],
      }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Alert mocks                                                       */
/* ------------------------------------------------------------------ */

const ALERT_SEED = [
  {
    id: 'ALR-1',
    type: 'Brute Force',
    severity: 'critical',
    status: 'new',
    timestamp: '2026-03-10T08:00:00Z',
    description: 'Repeated SSH login failures from 10.0.0.5',
    source: 'auth-service',
    tags: ['ssh', 'brute-force'],
    details: {},
  },
  {
    id: 'ALR-2',
    type: 'Port Scan',
    severity: 'medium',
    status: 'new',
    timestamp: '2026-03-10T09:30:00Z',
    description: 'Sequential port scan detected from 10.0.0.8',
    source: 'xdp-collector',
    tags: ['recon'],
    details: {},
  },
  {
    id: 'ALR-3',
    type: 'Malware Beacon',
    severity: 'high',
    status: 'acknowledged',
    timestamp: '2026-03-09T14:00:00Z',
    description: 'Outbound C2 beacon detected',
    source: 'hids-agent',
    tags: ['c2', 'malware'],
    details: {},
  },
]

const ALERT_STATS = { new: 2, acknowledged: 1, resolved: 0, ignored: 0 }

export const mockAlertRoutes = async (page: Page) => {
  // Match /api/v1/alerts, /api/v1/alerts?x=y, /api/v1/alerts/stats,
  // /api/v1/alerts/ALR-1/acknowledge, etc. The `?` alternative is the fix
  // for list requests carrying query params (e.g. ?severity=critical).
  await page.route(/\/api\/v1\/alerts(?:$|[/?])/, async (route) => {
    const url = route.request().url()
    const method = route.request().method()

    if (url.includes('/stats')) {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(ALERT_STATS) })
    }

    if (url.includes('/acknowledge') && method === 'POST') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'acknowledged' }) })
    }

    if (url.includes('/resolve') && method === 'POST') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'resolved' }) })
    }

    if (url.includes('/ignore') && method === 'POST') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'ignored' }) })
    }

    const urlObj = new URL(url)
    let filtered = [...ALERT_SEED]
    const severityParam = urlObj.searchParams.get('severity')
    const statusParam = urlObj.searchParams.get('status')
    if (severityParam) filtered = filtered.filter((a) => a.severity === severityParam)
    if (statusParam) filtered = filtered.filter((a) => a.status === statusParam)

    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ alerts: filtered, total: filtered.length }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Policy mocks                                                      */
/* ------------------------------------------------------------------ */

const POLICY_SEED = [
  {
    id: 'POL-1',
    name: 'Block SSH brute-force',
    description: 'Deny repeated SSH failures',
    source_cidr: '0.0.0.0/0',
    destination_cidr: '10.0.0.0/8',
    protocol: 'tcp',
    port_range: '22',
    action: 'deny',
    priority: 10,
    is_active: true,
    created_by: 'demo',
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-01-15T00:00:00Z',
  },
]

export const mockPolicyRoutes = async (page: Page) => {
  const policies = [...POLICY_SEED]

  await page.route(/\/api\/v1\/policies/, async (route) => {
    const method = route.request().method()

    if (method === 'POST') {
      const body = route.request().postDataJSON()
      const newPolicy = {
        ...body,
        id: `POL-${policies.length + 1}`,
        is_active: true,
        created_by: 'demo',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }
      policies.push(newPolicy)
      return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(newPolicy) })
    }

    if (method === 'PUT') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
    }

    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ policies }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Compliance mocks                                                  */
/* ------------------------------------------------------------------ */

const FRAMEWORKS = [
  { id: 'NIST', name: 'NIST 800-53', description: 'NIST security controls', version: '5.1', controls_count: 42, categories: ['AC', 'AU', 'CM'] },
  { id: 'PCI-DSS', name: 'PCI DSS', description: 'Payment card industry standard', version: '4.0', controls_count: 30, categories: ['Network', 'Access'] },
]

const ASSESSMENT_RESULT = {
  framework: 'NIST 800-53',
  overall_score: 88,
  status: 'partial',
  timestamp: '2026-03-13T00:00:00Z',
  controls_assessed: 42,
  controls_compliant: 37,
  controls_non_compliant: 3,
  controls_not_applicable: 2,
  details: [
    { control_id: 'AC-1', control_name: 'Access Control Policy', category: 'AC', status: 'compliant', findings: [] },
    { control_id: 'AU-2', control_name: 'Audit Events', category: 'AU', status: 'non_compliant', findings: ['Audit log rotation not configured'] },
  ],
}

export const mockComplianceRoutes = async (page: Page) => {
  await page.route('**/api/v1/frameworks', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ frameworks: FRAMEWORKS }),
    })
  })

  await page.route('**/api/v1/assess', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(ASSESSMENT_RESULT),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Users mocks                                                       */
/* ------------------------------------------------------------------ */

const USERS_SEED = [
  { ...demoUser },
  { id: 2, username: 'analyst', email: 'analyst@sentinel.local', role: 'security_analyst', status: 'active', created_at: '2026-02-01T00:00:00Z', last_login: '2026-03-12T10:00:00Z' },
  { id: 3, username: 'viewer1', email: 'viewer1@sentinel.local', role: 'viewer', status: 'active', created_at: '2026-02-15T00:00:00Z', last_login: null },
]

export const mockUserRoutes = async (page: Page) => {
  await page.route(/\/api\/v1\/admin\/users/, async (route) => {
    const method = route.request().method()

    if (method === 'PUT') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
    }

    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ users: USERS_SEED }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Settings / config mocks                                           */
/* ------------------------------------------------------------------ */

export const mockSettingsRoutes = async (page: Page) => {
  await page.route('**/api/v1/config', async (route) => {
    const method = route.request().method()

    if (method === 'PUT') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true }) })
    }

    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ai_engine: { confidence_threshold: 0.85 }, monitoring: {} }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Audit log mocks                                                   */
/* ------------------------------------------------------------------ */

const AUDIT_EVENTS = [
  { id: 'EVT-1', event_type: 'login', user: 'demo', resource: '/auth/login', result: 'success' as const, ip_address: '10.0.0.1', timestamp: '2026-03-13T08:00:00Z' },
  { id: 'EVT-2', event_type: 'policy_change', user: 'demo', resource: 'POL-1', result: 'success' as const, ip_address: '10.0.0.1', timestamp: '2026-03-13T08:05:00Z' },
  { id: 'EVT-3', event_type: 'login_failure', user: 'unknown', resource: '/auth/login', result: 'failure' as const, ip_address: '192.168.1.99', timestamp: '2026-03-13T07:55:00Z' },
]

export const mockAuditRoutes = async (page: Page) => {
  await page.route('**/api/v1/audit/events**', async (route) => {
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ events: AUDIT_EVENTS, total: AUDIT_EVENTS.length }),
    })
  })
}

/* ------------------------------------------------------------------ */
/*  Catch-all: stub every /api/v1 route not already mocked so the     */
/*  app never hangs waiting on a real backend.                        */
/* ------------------------------------------------------------------ */

export const mockAllApiRoutes = async (page: Page) => {
  await mockAuthRoutes(page)
  await mockDashboardRoutes(page)
  await mockThreatRoutes(page)
  await mockAlertRoutes(page)
  await mockPolicyRoutes(page)
  await mockComplianceRoutes(page)
  await mockUserRoutes(page)
  await mockSettingsRoutes(page)
  await mockAuditRoutes(page)
}

/**
 * Catch-all fallback that stubs every /api/** request not already handled by a
 * more specific mock. Register BEFORE specific mocks — Playwright runs the
 * most-recently-registered matching route first, so earlier registration
 * means "tried last". Prevents the Vite dev proxy from reaching a
 * non-existent backend and logging ECONNREFUSED.
 */
export const mockFallback = async (page: Page) => {
  await page.route('**/api/**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    })
  })
}

/** Heading text that appears on the dashboard when loaded (used as post-login assertion). */
const DASHBOARD_HEADING = 'Security Overview'

/** Seed localStorage with authenticated state so app loads already logged in (avoids post-login render issues in E2E). */
export const seedAuthState = async (page: Page) => {
  await page.addInitScript(() => {
    // Zustand persist format; use version 0 so no migration is required (store has no migrate)
    const state = {
      state: {
        isAuthenticated: true,
        user: {
          id: 1,
          username: 'demo',
          email: 'demo@sentinel.local',
          role: 'admin',
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
          last_login: null,
        },
        token: 'test-access-token',
        refreshToken: 'test-refresh-token',
      },
      version: 0,
    }
    localStorage.setItem('sentinel-auth', JSON.stringify(state))
    localStorage.setItem('sentinel-token', 'test-access-token')
    localStorage.setItem('sentinel-refresh-token', 'test-refresh-token')
  })
}

/** Perform login via UI and wait for redirect to dashboard; does not assert dashboard content. */
export const loginViaUiOnly = async (page: Page) => {
  await page.goto('/login')
  await page.fill('#username', 'demo')
  await page.fill('#password', 'demo-token')
  const loginResponse = page.waitForResponse(
    (resp) => resp.url().includes('/api/v1/auth/login') && resp.status() === 200,
    { timeout: 15_000 }
  )
  await page.click('button[type="submit"]')
  await loginResponse
  await expect(page).toHaveURL('/', { timeout: 15_000 })
  await page.waitForLoadState('networkidle').catch(() => {})
}

export const loginViaUi = async (page: Page) => {
  await loginViaUiOnly(page)
  await expect(
    page.getByRole('heading', { name: DASHBOARD_HEADING })
  ).toBeVisible({ timeout: 15_000 })
}

/** Go to app root with auth pre-seeded and wait for dashboard (avoids login form + post-login render). */
export const gotoDashboard = async (page: Page) => {
  await page.goto('/')
  await expect(
    page.getByRole('heading', { name: DASHBOARD_HEADING })
  ).toBeVisible({ timeout: 15_000 })
}
