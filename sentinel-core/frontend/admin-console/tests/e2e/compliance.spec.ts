import { test, expect } from '@playwright/test'
import { mockComplianceRoutes, mockAuthRoutes, seedAuthState } from './helpers'

test.describe('Compliance — assessment workflow', () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthRoutes(page)
    await mockComplianceRoutes(page)
    await seedAuthState(page)
  })

  test('renders compliance overview with framework cards', async ({ page }) => {
    await page.goto('/compliance')

    await expect(page.getByRole('heading', { name: 'Compliance Overview' })).toBeVisible()
    await expect(page.getByText('NIST 800-53')).toBeVisible()
    await expect(page.getByText('PCI DSS')).toBeVisible()
    await expect(page.getByText('42 controls')).toBeVisible()
    await expect(page.getByText('30 controls')).toBeVisible()
  })

  test('shows framework descriptions and versions', async ({ page }) => {
    await page.goto('/compliance')

    await expect(page.getByText('NIST security controls')).toBeVisible()
    await expect(page.getByText('Payment card industry standard')).toBeVisible()
    await expect(page.getByText('v5.1')).toBeVisible()
    await expect(page.getByText('v4.0')).toBeVisible()
  })

  test('runs an assessment and displays results', async ({ page }) => {
    await page.goto('/compliance')

    const assessReq = page.waitForRequest(
      (req) => req.url().includes('/api/v1/assess') && req.method() === 'POST',
    )

    const nistCard = page.locator('.card', { hasText: 'NIST 800-53' })
    await nistCard.getByRole('button', { name: 'Run Assessment' }).click()

    const req = await assessReq
    const body = req.postDataJSON()
    expect(body.framework).toBe('NIST')

    await expect(page.getByText('Assessment Results')).toBeVisible()
    await expect(page.getByText('88%')).toBeVisible()
  })

  test('assessment results show compliant/non-compliant counts', async ({ page }) => {
    await page.goto('/compliance')

    const nistCard = page.locator('.card', { hasText: 'NIST 800-53' })
    await nistCard.getByRole('button', { name: 'Run Assessment' }).click()

    await expect(page.getByText('37 Compliant')).toBeVisible()
    await expect(page.getByText('3 Non-compliant')).toBeVisible()
    await expect(page.getByText('2 N/A')).toBeVisible()
  })

  test('assessment results table shows control details', async ({ page }) => {
    await page.goto('/compliance')

    const nistCard = page.locator('.card', { hasText: 'NIST 800-53' })
    await nistCard.getByRole('button', { name: 'Run Assessment' }).click()

    await expect(page.getByText('AC-1')).toBeVisible()
    await expect(page.getByText('Access Control Policy')).toBeVisible()
    await expect(page.getByText('AU-2')).toBeVisible()
    await expect(page.getByText('Audit log rotation not configured')).toBeVisible()
  })

  test('can close assessment results', async ({ page }) => {
    await page.goto('/compliance')

    const nistCard = page.locator('.card', { hasText: 'NIST 800-53' })
    await nistCard.getByRole('button', { name: 'Run Assessment' }).click()
    await expect(page.getByText('Assessment Results')).toBeVisible()

    await page.getByRole('button', { name: 'Close' }).click()
    await expect(page.getByText('Assessment Results')).not.toBeVisible()
  })
})
