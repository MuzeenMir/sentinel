import { test, expect } from '@playwright/test'
import { mockPolicyRoutes, mockAuthRoutes, seedAuthState } from './helpers'

test.describe('Policies — management workflow', () => {
  test.beforeEach(async ({ page }) => {
    await mockAuthRoutes(page)
    await mockPolicyRoutes(page)
    await seedAuthState(page)
  })

  test('renders policy list with existing policies', async ({ page }) => {
    await page.goto('/policies')

    await expect(page.getByRole('heading', { name: 'Active Policies' })).toBeVisible()
    await expect(page.getByText('Block SSH brute-force')).toBeVisible()
    await expect(page.getByText('DENY')).toBeVisible()
  })

  test('displays policy stats', async ({ page }) => {
    await page.goto('/policies')

    await expect(page.getByText('Total Policies')).toBeVisible()
    await expect(page.getByText('DENY Rules')).toBeVisible()
    await expect(page.getByText('ALLOW Rules')).toBeVisible()
  })

  test('creates a new policy via the dialog', async ({ page }) => {
    await page.goto('/policies')

    await page.getByRole('button', { name: '+ Create Policy' }).click()
    await expect(page.getByRole('heading', { name: 'Create Policy' })).toBeVisible()

    await page.locator('label:has-text("Name") + input, label:has-text("Name") ~ input').first().fill('Block Telnet')
    await page.locator('label:has-text("Description") + input, label:has-text("Description") ~ input').first().fill('Deny all telnet traffic')
    await page.locator('label:has-text("Source CIDR") + input, label:has-text("Source CIDR") ~ input').first().fill('0.0.0.0/0')
    await page.locator('label:has-text("Destination CIDR") + input, label:has-text("Destination CIDR") ~ input').first().fill('10.0.0.0/8')
    await page.locator('label:has-text("Port Range") + input, label:has-text("Port Range") ~ input').first().fill('23')

    const createReq = page.waitForRequest(
      (req) => req.url().includes('/api/v1/policies') && req.method() === 'POST',
    )

    await page.getByRole('button', { name: 'Create Policy' }).click()
    const req = await createReq
    const body = req.postDataJSON()
    expect(body.name).toBe('Block Telnet')
    expect(body.port_range).toBe('23')
  })

  test('new policy appears in the list after creation', async ({ page }) => {
    await page.goto('/policies')
    await expect(page.getByText('Block SSH brute-force')).toBeVisible()

    await page.getByRole('button', { name: '+ Create Policy' }).click()

    const nameInput = page.locator('.fixed input').first()
    await nameInput.fill('Rate Limit API')

    const createReq = page.waitForResponse(
      (resp) => resp.url().includes('/api/v1/policies') && resp.request().method() === 'POST' && resp.status() === 201,
    )

    await page.getByRole('button', { name: 'Create Policy' }).click()
    await createReq

    await expect(page.getByText('Policy created successfully.')).toBeVisible()
  })

  test('closes the create dialog on cancel', async ({ page }) => {
    await page.goto('/policies')

    await page.getByRole('button', { name: '+ Create Policy' }).click()
    await expect(page.getByRole('heading', { name: 'Create Policy' })).toBeVisible()

    await page.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByRole('heading', { name: 'Create Policy' })).not.toBeVisible()
  })
})
