import { test, expect } from '@playwright/test'
import { mockSettingsRoutes, mockAuthRoutes, seedAuthState } from './helpers'

test.describe('Settings — persistence workflow', () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthRoutes(page)
    await mockSettingsRoutes(page)
    await seedAuthState(page)
  })

  test('renders all settings sections', async ({ page }) => {
    await page.goto('/settings')

    await expect(page.getByRole('heading', { name: 'Platform' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'General Settings' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Detection Settings' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible()
  })

  test('organization name can be changed', async ({ page }) => {
    await page.goto('/settings')

    const orgInput = page.locator('label:has-text("Organization Name")').locator('..').locator('input')
    await expect(orgInput).toHaveValue('SENTINEL Security')

    await orgInput.fill('Acme Corp Security')
    await expect(orgInput).toHaveValue('Acme Corp Security')
  })

  test('timezone can be changed', async ({ page }) => {
    await page.goto('/settings')

    const tzSelect = page.locator('label:has-text("Default Timezone")').locator('..').locator('select')
    await expect(tzSelect).toHaveValue('UTC')

    await tzSelect.selectOption('America/New_York')
    await expect(tzSelect).toHaveValue('America/New_York')
  })

  test('toggle switches work for detection settings', async ({ page }) => {
    await page.goto('/settings')

    const autoBlockToggle = page.locator('text=Auto-block High Threats').locator('..').locator('..').locator('input[type="checkbox"]')
    await expect(autoBlockToggle).toBeChecked()

    await autoBlockToggle.click()
    await expect(autoBlockToggle).not.toBeChecked()

    await autoBlockToggle.click()
    await expect(autoBlockToggle).toBeChecked()
  })

  test('saving settings calls the API', async ({ page }) => {
    await page.goto('/settings')

    const orgInput = page.locator('label:has-text("Organization Name")').locator('..').locator('input')
    await orgInput.fill('New Org Name')

    const saveReq = page.waitForRequest(
      (req) => req.url().includes('/api/v1/config') && req.method() === 'PUT',
    )

    await page.getByRole('button', { name: 'Save Settings' }).click()

    const req = await saveReq
    const body = req.postDataJSON()
    expect(body.organization.name).toBe('New Org Name')
  })

  test('shows success message after saving', async ({ page }) => {
    await page.goto('/settings')

    await page.getByRole('button', { name: 'Save Settings' }).click()
    await expect(page.getByText('Settings saved to backend successfully.')).toBeVisible()
  })

  test('settings persist across page reload via localStorage', async ({ page }) => {
    await page.goto('/settings')

    const orgInput = page.locator('label:has-text("Organization Name")').locator('..').locator('input')
    await orgInput.fill('Persisted Org')

    await page.getByRole('button', { name: 'Save Settings' }).click()
    await expect(page.getByText('Settings saved to backend successfully.')).toBeVisible()

    await page.reload()

    const orgInputAfter = page.locator('label:has-text("Organization Name")').locator('..').locator('input')
    await expect(orgInputAfter).toHaveValue('Persisted Org')
  })
})
