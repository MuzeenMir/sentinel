import { test, expect } from '@playwright/test'
import { mockUserRoutes, mockAuthRoutes, seedAuthState } from './helpers'

test.describe('Users — management workflow', () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthRoutes(page)
    await mockUserRoutes(page)
    await seedAuthState(page)
  })

  test('renders user list with role permissions reference', async ({ page }) => {
    await page.goto('/users')

    await expect(page.getByRole('heading', { name: 'Users & RBAC' })).toBeVisible()
    await expect(page.getByText('Role Permissions')).toBeVisible()
    await expect(page.getByText('Full access')).toBeVisible()
  })

  test('displays all seeded users in the table', async ({ page }) => {
    await page.goto('/users')

    await expect(page.getByText('demo')).toBeVisible()
    await expect(page.getByText('analyst')).toBeVisible()
    await expect(page.getByText('viewer1')).toBeVisible()

    await expect(page.getByText('demo@sentinel.local')).toBeVisible()
    await expect(page.getByText('analyst@sentinel.local')).toBeVisible()
  })

  test('marks current user with (you) indicator', async ({ page }) => {
    await page.goto('/users')

    await expect(page.getByText('(you)')).toBeVisible()
  })

  test('current user row has no edit button', async ({ page }) => {
    await page.goto('/users')

    const demoRow = page.locator('table tbody tr', { hasText: 'demo@sentinel.local' })
    await expect(demoRow.getByText('—')).toBeVisible()
  })

  test('opens inline edit for another user', async ({ page }) => {
    await page.goto('/users')

    const analystRow = page.locator('table tbody tr', { hasText: 'analyst@sentinel.local' })
    await analystRow.getByRole('button', { name: 'Edit' }).click()

    await expect(analystRow.locator('select').first()).toBeVisible()
    await expect(analystRow.getByRole('button', { name: 'Save' })).toBeVisible()
    await expect(analystRow.getByRole('button', { name: 'Cancel' })).toBeVisible()
  })

  test('updates a user role', async ({ page }) => {
    await page.goto('/users')

    const analystRow = page.locator('table tbody tr', { hasText: 'analyst@sentinel.local' })
    await analystRow.getByRole('button', { name: 'Edit' }).click()

    const roleSelect = analystRow.locator('select').first()
    await roleSelect.selectOption('auditor')

    const updateReq = page.waitForRequest(
      (req) => req.url().includes('/api/v1/admin/users/2') && req.method() === 'PUT',
    )

    await analystRow.getByRole('button', { name: 'Save' }).click()

    const req = await updateReq
    const body = req.postDataJSON()
    expect(body.role).toBe('auditor')
  })

  test('cancels inline edit without saving', async ({ page }) => {
    await page.goto('/users')

    const analystRow = page.locator('table tbody tr', { hasText: 'analyst@sentinel.local' })
    await analystRow.getByRole('button', { name: 'Edit' }).click()
    await expect(analystRow.locator('select').first()).toBeVisible()

    await analystRow.getByRole('button', { name: 'Cancel' }).click()
    await expect(analystRow.locator('select')).not.toBeVisible()
    await expect(analystRow.getByRole('button', { name: 'Edit' })).toBeVisible()
  })
})
