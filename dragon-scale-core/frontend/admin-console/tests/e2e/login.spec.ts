import { test, expect } from '@playwright/test'
import { mockDashboardRoutes, mockFallback, seedAuthState, gotoDashboard } from './helpers'

test('user can sign in and reach dashboard', async ({ page }) => {
  await mockFallback(page)
  await mockDashboardRoutes(page)
  await seedAuthState(page)
  await gotoDashboard(page)
  await expect(page).toHaveURL('/')
})
