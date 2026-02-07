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
    page.getByRole('heading', { name: DASHBOARD_HEADING, level: 3 })
  ).toBeVisible({ timeout: 15_000 })
}

/** Go to app root with auth pre-seeded and wait for dashboard (avoids login form + post-login render). */
export const gotoDashboard = async (page: Page) => {
  await page.goto('/')
  await expect(
    page.getByRole('heading', { name: DASHBOARD_HEADING, level: 3 })
  ).toBeVisible({ timeout: 15_000 })
}
