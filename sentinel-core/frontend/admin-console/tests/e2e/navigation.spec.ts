import { test, expect } from '@playwright/test'
import {
  seedAuthState,
  mockAllApiRoutes,
  mockAuthRoutes,
  mockDashboardRoutes,
} from './helpers'

test.describe('Navigation — sidebar & auth guards', () => {
  test.describe('authenticated navigation', () => {
    test.beforeEach(async ({ page }) => {
      await mockAllApiRoutes(page)
      await seedAuthState(page)
    })

    const navTargets = [
      { name: 'Dashboard', path: '/', heading: 'Security Overview' },
      { name: 'Threats', path: '/threats', heading: 'Threats' },
      { name: 'Alerts', path: '/alerts', heading: 'Alerts' },
      { name: 'Policies', path: '/policies', heading: 'Active Policies' },
      { name: 'Compliance', path: '/compliance', heading: 'Compliance Overview' },
      { name: 'Users', path: '/users', heading: 'Users & RBAC' },
      { name: 'Audit Log', path: '/audit', heading: 'Audit Log' },
      { name: 'Settings', path: '/settings', heading: 'Platform' },
    ]

    for (const { name, path, heading } of navTargets) {
      test(`sidebar link navigates to ${name} (${path})`, async ({ page }) => {
        await page.goto('/')
        await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible({ timeout: 10_000 })

        const sidebarLink = page.locator('aside a', { hasText: name }).first()
        await sidebarLink.click()

        await expect(page).toHaveURL(path)
        await expect(page.getByText(heading).first()).toBeVisible({ timeout: 10_000 })
      })
    }

    test('sidebar highlights the active page', async ({ page }) => {
      await page.goto('/alerts')

      const alertsLink = page.locator('aside a', { hasText: 'Alerts' }).first()
      await expect(alertsLink).toHaveClass(/bg-blue-600/)
    })

    test('header shows the active workspace name', async ({ page }) => {
      await page.goto('/policies')

      const header = page.locator('header')
      await expect(header.getByText('Policies')).toBeVisible()
    })
  })

  test.describe('unauthenticated access', () => {
    test.beforeEach(async ({ page }) => {
      await mockAuthRoutes(page)
    })

    test('visiting root without auth shows authentication required', async ({ page }) => {
      await page.goto('/')

      await expect(page.getByText('Authentication Required')).toBeVisible()
      await expect(page.getByRole('link', { name: 'Sign in' })).toBeVisible()
    })

    test('visiting a protected route without auth does not render the page', async ({ page }) => {
      await page.goto('/alerts')

      await expect(page.getByText('Authentication Required')).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Alerts' })).not.toBeVisible()
    })

    test('sign-in link navigates to login page', async ({ page }) => {
      await page.goto('/policies')

      await page.getByRole('link', { name: 'Sign in' }).click()
      await expect(page).toHaveURL('/login')
    })
  })

  test.describe('post-login redirect', () => {
    test('after login, user lands on dashboard', async ({ page }) => {
      await mockAuthRoutes(page)
      await mockDashboardRoutes(page)

      await page.goto('/login')
      await page.fill('#username', 'demo')
      await page.fill('#password', 'demo-token')

      const loginResp = page.waitForResponse(
        (resp) => resp.url().includes('/api/v1/auth/login') && resp.status() === 200,
        { timeout: 15_000 },
      )

      await page.click('button[type="submit"]')
      await loginResp

      await expect(page).toHaveURL('/', { timeout: 15_000 })
    })
  })

  test.describe('user profile menu', () => {
    test.beforeEach(async ({ page }) => {
      await mockAllApiRoutes(page)
      await seedAuthState(page)
    })

    test('profile dropdown shows username and logout option', async ({ page }) => {
      await page.goto('/')
      await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible({ timeout: 10_000 })

      const profileButton = page.locator('[aria-label="User menu"]')
      await profileButton.click()

      const menu = page.locator('[role="menu"]')
      await expect(menu).toBeVisible()
      await expect(menu.getByText('Settings')).toBeVisible()
      await expect(menu.getByText('Log out')).toBeVisible()
    })

    test('profile menu settings link navigates to settings', async ({ page }) => {
      await page.goto('/')
      await expect(page.getByRole('heading', { name: 'Security Overview' })).toBeVisible({ timeout: 10_000 })

      await page.locator('[aria-label="User menu"]').click()
      await page.locator('[role="menu"]').getByText('Settings').click()

      await expect(page).toHaveURL('/settings')
    })
  })
})
