import { test, expect } from '@playwright/test'
import { mockAlertRoutes, mockAuthRoutes, mockFallback, seedAuthState } from './helpers'

test.describe('Alerts — triage workflow', () => {
  test.beforeEach(async ({ page }) => {
    await mockFallback(page)
    await mockAuthRoutes(page)
    await mockAlertRoutes(page)
    await seedAuthState(page)
  })

  test('renders alert list with severity badges', async ({ page }) => {
    await page.goto('/alerts')

    await expect(page.getByRole('heading', { name: 'Alerts' })).toBeVisible()

    const rows = page.locator('table tbody tr')
    await expect(rows).toHaveCount(3)

    const tbody = page.locator('table tbody')
    await expect(tbody.getByText('Brute Force').first()).toBeVisible()
    await expect(tbody.getByText('Port Scan').first()).toBeVisible()
    await expect(tbody.getByText('Malware Beacon').first()).toBeVisible()

    const criticalBadge = rows.nth(0).locator('.badge-critical', { hasText: 'critical' })
    await expect(criticalBadge).toBeVisible()

    const mediumBadge = rows.nth(1).locator('.badge-medium', { hasText: 'medium' })
    await expect(mediumBadge).toBeVisible()
  })

  test('displays alert stats cards', async ({ page }) => {
    await page.goto('/alerts')

    await expect(page.getByText('New', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('Acknowledged', { exact: true }).first()).toBeVisible()
    await expect(page.getByText('Resolved', { exact: true }).first()).toBeVisible()
  })

  test('filters alerts by severity', async ({ page }) => {
    await page.goto('/alerts')
    await expect(page.locator('table tbody tr')).toHaveCount(3)

    const severitySelect = page.locator('select').nth(0)
    await severitySelect.selectOption('critical')

    const tbody = page.locator('table tbody')
    await expect(tbody.getByText('Brute Force').first()).toBeVisible()
    await expect(tbody.getByText('Port Scan')).toHaveCount(0)
  })

  test('filters alerts by status', async ({ page }) => {
    await page.goto('/alerts')
    await expect(page.locator('table tbody tr')).toHaveCount(3)

    const statusSelect = page.locator('select').nth(1)
    await statusSelect.selectOption('acknowledged')

    const tbody = page.locator('table tbody')
    await expect(tbody.getByText('Malware Beacon').first()).toBeVisible()
    await expect(tbody.getByText('Brute Force')).toHaveCount(0)
  })

  test('acknowledges an alert', async ({ page }) => {
    await page.goto('/alerts')

    const ackRequest = page.waitForRequest(
      (req) => req.url().includes('/alerts/ALR-1/acknowledge') && req.method() === 'POST',
    )

    const firstRow = page.locator('table tbody tr').first()
    await firstRow.getByRole('button', { name: 'Acknowledge' }).click()

    const req = await ackRequest
    expect(req.method()).toBe('POST')
  })

  test('resolves an alert', async ({ page }) => {
    await page.goto('/alerts')

    const resolveRequest = page.waitForRequest(
      (req) => req.url().includes('/alerts/ALR-1/resolve') && req.method() === 'POST',
    )

    const firstRow = page.locator('table tbody tr').first()
    await firstRow.getByRole('button', { name: 'Resolve' }).click()

    const req = await resolveRequest
    expect(req.method()).toBe('POST')
  })

  test('shows empty state when filters match nothing', async ({ page }) => {
    await page.route(/\/api\/v1\/alerts(?!\/)/, async (route) => {
      if (route.request().url().includes('/stats')) return route.continue()
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ alerts: [], total: 0 }),
      })
    })

    await page.goto('/alerts')
    await expect(page.getByText('No alerts match the current filters.')).toBeVisible()
  })
})
