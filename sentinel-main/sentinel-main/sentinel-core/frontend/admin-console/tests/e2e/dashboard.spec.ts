import { test, expect } from '@playwright/test'
import { mockDashboardRoutes, seedAuthState, gotoDashboard } from './helpers'

test('dashboard renders key stats', async ({ page }) => {
  await mockDashboardRoutes(page)
  await seedAuthState(page)
  await gotoDashboard(page)

  await expect(page.getByText('Total Threats')).toBeVisible()
  await expect(page.getByText('Blocked Threats')).toBeVisible()
  await expect(page.getByText('Active Policies')).toBeVisible()
  await expect(page.getByText('Compliance Score')).toBeVisible()
})
