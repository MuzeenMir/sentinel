import { test, expect } from '@playwright/test'
import { mockThreatRoutes, mockFallback, seedAuthState } from './helpers'

test('threats list renders and can filter', async ({ page }) => {
  await mockFallback(page)
  await mockThreatRoutes(page)
  await seedAuthState(page)
  await page.goto('/threats')

  await expect(page.getByRole('heading', { name: 'Threats' })).toBeVisible()
  const tbody = page.locator('table tbody')
  await expect(tbody.getByText('DDoS Attack')).toBeVisible()

  await page.locator('select').first().selectOption('critical')
  await expect(tbody.getByText('DDoS Attack')).toBeVisible()
})
