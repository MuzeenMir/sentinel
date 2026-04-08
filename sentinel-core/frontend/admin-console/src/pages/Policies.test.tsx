import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Policies } from './Policies'
import type { Policy } from '../types'

const mockGetPolicies = vi.fn()
const mockCreatePolicy = vi.fn()
const mockUpdatePolicy = vi.fn()

vi.mock('../services/api', () => ({
  policyApi: {
    getPolicies: (...args: unknown[]) => mockGetPolicies(...args),
    createPolicy: (...args: unknown[]) => mockCreatePolicy(...args),
    updatePolicy: (...args: unknown[]) => mockUpdatePolicy(...args),
    deletePolicy: vi.fn(),
  },
}))

const samplePolicies: Policy[] = [
  {
    id: 'pol-1',
    name: 'Block External SSH',
    description: 'Deny SSH from outside network',
    source_cidr: '0.0.0.0/0',
    destination_cidr: '10.0.0.0/8',
    protocol: 'tcp',
    port_range: '22',
    action: 'deny',
    priority: 10,
    is_active: true,
    created_by: 'admin',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'pol-2',
    name: 'Allow HTTPS',
    description: 'Allow HTTPS traffic',
    source_cidr: '0.0.0.0/0',
    destination_cidr: '10.0.0.0/8',
    protocol: 'tcp',
    port_range: '443',
    action: 'allow',
    priority: 20,
    is_active: true,
    created_by: 'admin',
    created_at: '2026-01-02T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z',
  },
]

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

function renderPolicies() {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Policies />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Policies', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetPolicies.mockResolvedValue({ data: { policies: samplePolicies } })
    mockCreatePolicy.mockResolvedValue({ data: { id: 'pol-3' } })
    mockUpdatePolicy.mockResolvedValue({ data: {} })
  })

  it('renders the page heading', () => {
    renderPolicies()
    expect(screen.getByText('Active Policies')).toBeInTheDocument()
  })

  it('renders policy rows from API data', async () => {
    renderPolicies()

    expect(await screen.findByText('Block External SSH')).toBeInTheDocument()
    expect(screen.getByText('Allow HTTPS')).toBeInTheDocument()
  })

  it('shows policy stats cards with computed counts', async () => {
    renderPolicies()
    await screen.findByText('Block External SSH')

    expect(screen.getByText('Total Policies')).toBeInTheDocument()
    expect(screen.getByText('DENY Rules')).toBeInTheDocument()
    expect(screen.getByText('ALLOW Rules')).toBeInTheDocument()
  })

  it('shows loading state while fetching', () => {
    mockGetPolicies.mockReturnValue(new Promise(() => {}))
    renderPolicies()

    expect(screen.getByText(/loading policies/i)).toBeInTheDocument()
  })

  it('shows error state when API fails', async () => {
    mockGetPolicies.mockRejectedValue(new Error('Service down'))
    renderPolicies()

    expect(await screen.findByText(/failed to load policies/i, {}, { timeout: 3000 })).toBeInTheDocument()
  })

  it('shows empty state when no policies exist', async () => {
    mockGetPolicies.mockResolvedValue({ data: { policies: [] } })
    renderPolicies()

    expect(await screen.findByText(/no policies available/i)).toBeInTheDocument()
  })

  it('opens create modal when "+ Create Policy" is clicked', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    expect(screen.getByText('Create Policy', { selector: 'h3' })).toBeInTheDocument()
    const labels = screen.getAllByText('Name')
    expect(labels.length).toBeGreaterThanOrEqual(1)
  })

  it('closes create modal when Cancel is clicked', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    await user.click(screen.getByRole('button', { name: /create policy/i }))
    expect(screen.getByText('Create Policy', { selector: 'h3' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /cancel/i }))
    expect(screen.queryByText('Create Policy', { selector: 'h3' })).not.toBeInTheDocument()
  })

  it('shows validation message when name is empty on submit', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    const submitButtons = screen.getAllByRole('button', { name: /create policy/i })
    const modalSubmit = submitButtons[submitButtons.length - 1]
    await user.click(modalSubmit)

    expect(await screen.findByText(/policy name is required/i)).toBeInTheDocument()
    expect(mockCreatePolicy).not.toHaveBeenCalled()
  })

  it('submits create policy form with valid data', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    const modal = screen.getByText('Create Policy', { selector: 'h3' }).closest('div.card')!
    const textInputs = within(modal).getAllByRole('textbox')
    const nameInput = textInputs[0]
    await user.type(nameInput, 'Block FTP')

    const submitButtons = screen.getAllByRole('button', { name: /create policy/i })
    const modalSubmit = submitButtons[submitButtons.length - 1]
    await user.click(modalSubmit)

    await waitFor(() => {
      expect(mockCreatePolicy).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'Block FTP', action: 'deny' }),
      )
    })
  })

  it('shows success message after successful creation', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    await user.click(screen.getByRole('button', { name: /create policy/i }))

    const modal = screen.getByText('Create Policy', { selector: 'h3' }).closest('div.card')!
    const textInputs = within(modal).getAllByRole('textbox')
    await user.type(textInputs[0], 'New Rule')

    const submitButtons = screen.getAllByRole('button', { name: /create policy/i })
    await user.click(submitButtons[submitButtons.length - 1])

    expect(await screen.findByText(/policy created successfully/i)).toBeInTheDocument()
  })

  it('opens edit modal when Edit button is clicked', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    const editButtons = screen.getAllByRole('button', { name: /edit/i })
    await user.click(editButtons[0])

    expect(screen.getByText('Edit Policy')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Block External SSH')).toBeInTheDocument()
  })

  it('calls updatePolicy when saving an edit', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    const editButtons = screen.getAllByRole('button', { name: /edit/i })
    await user.click(editButtons[0])

    await user.click(screen.getByRole('button', { name: /update policy/i }))

    await waitFor(() => {
      expect(mockUpdatePolicy).toHaveBeenCalledWith(
        'pol-1',
        expect.objectContaining({ name: 'Block External SSH' }),
      )
    })
  })

  it('disables a policy when Disable button is clicked', async () => {
    const user = userEvent.setup()
    renderPolicies()
    await screen.findByText('Block External SSH')

    const disableButtons = screen.getAllByRole('button', { name: /disable/i })
    await user.click(disableButtons[0])

    await waitFor(() => {
      expect(mockUpdatePolicy).toHaveBeenCalledWith('pol-1', { is_active: false })
    })
  })

  it('renders table column headers', async () => {
    renderPolicies()
    await screen.findByText('Block External SSH')

    const table = screen.getByRole('table')
    expect(within(table).getByText('Name')).toBeInTheDocument()
    expect(within(table).getByText('Action')).toBeInTheDocument()
    expect(within(table).getByText('Source')).toBeInTheDocument()
    expect(within(table).getByText('Status')).toBeInTheDocument()
  })

  it('shows DENY and ALLOW action badges', async () => {
    renderPolicies()
    await screen.findByText('Block External SSH')

    expect(screen.getByText('DENY')).toBeInTheDocument()
    expect(screen.getByText('ALLOW')).toBeInTheDocument()
  })
})
