import { test, expect } from '@playwright/test'
import { mockThreatRoutes, seedAuthState } from './helpers'

test('threats list renders and can filter', async ({ page }) => {
  await mockThreatRoutes(page)
  await seedAuthState(page)
  await page.goto('/threats')

  await expect(page.getByRole('heading', { name: 'Threats', level: 2 })).toBeVisible()
  await expect(page.getByText('DDoS Attack')).toBeVisible()

  await page.getByRole('button', { name: 'critical' }).click()
  await expect(page.getByText('DDoS Attack')).toBeVisible()
})
