import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Alerts } from './Alerts'
import type { Alert } from '../types'

const mockGetAlerts = vi.fn()
const mockGetStats = vi.fn()
const mockAcknowledge = vi.fn()
const mockResolve = vi.fn()
const mockIgnore = vi.fn()

vi.mock('../services/api', () => ({
  alertApi: {
    getAlerts: (...args: unknown[]) => mockGetAlerts(...args),
    getStats: (...args: unknown[]) => mockGetStats(...args),
    acknowledge: (...args: unknown[]) => mockAcknowledge(...args),
    resolve: (...args: unknown[]) => mockResolve(...args),
    ignore: (...args: unknown[]) => mockIgnore(...args),
  },
}))

const sampleAlerts: Alert[] = [
  {
    id: 'alert-1',
    type: 'DDoS Attack',
    severity: 'critical',
    status: 'new',
    timestamp: '2026-03-13T10:00:00Z',
    description: 'Massive traffic spike detected',
    details: {},
    source: '10.0.0.1',
    tags: ['network'],
  },
  {
    id: 'alert-2',
    type: 'Port Scan',
    severity: 'high',
    status: 'acknowledged',
    timestamp: '2026-03-13T09:30:00Z',
    description: 'Sequential port scan from external IP',
    details: {},
    source: '192.168.1.50',
    tags: ['scan'],
  },
  {
    id: 'alert-3',
    type: 'Brute Force',
    severity: 'medium',
    status: 'resolved',
    timestamp: '2026-03-13T08:00:00Z',
    description: 'Multiple failed SSH login attempts',
    details: {},
    source: '172.16.0.25',
    tags: ['auth'],
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

function renderAlerts() {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Alerts />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Alerts', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetAlerts.mockResolvedValue({ data: { alerts: sampleAlerts, total: 3 } })
    mockGetStats.mockResolvedValue({ data: { new: 1, acknowledged: 1, resolved: 1, ignored: 0 } })
    mockAcknowledge.mockResolvedValue({})
    mockResolve.mockResolvedValue({})
    mockIgnore.mockResolvedValue({})
  })

  it('renders the page heading', async () => {
    renderAlerts()

    expect(screen.getByRole('heading', { name: /alerts/i })).toBeInTheDocument()
    expect(await screen.findByText('DDoS Attack')).toBeInTheDocument()
  })

  it('renders alert rows from API data', async () => {
    renderAlerts()

    expect(await screen.findByText('DDoS Attack')).toBeInTheDocument()
    expect(screen.getByText('Port Scan')).toBeInTheDocument()
    expect(screen.getByText('Brute Force')).toBeInTheDocument()
  })

  it('shows alert stats cards', async () => {
    renderAlerts()

    expect(await screen.findByText('DDoS Attack')).toBeInTheDocument()

    const newCards = screen.getAllByText('New')
    expect(newCards.length).toBeGreaterThanOrEqual(1)
  })

  it('shows loading state', () => {
    mockGetAlerts.mockReturnValue(new Promise(() => {}))
    renderAlerts()

    expect(screen.getByText(/loading alerts/i)).toBeInTheDocument()
  })

  it('shows error state when API fails', async () => {
    mockGetAlerts.mockRejectedValue(new Error('Service down'))
    renderAlerts()

    expect(await screen.findByText(/failed to load alerts/i)).toBeInTheDocument()
  })

  it('shows empty state when no alerts match filters', async () => {
    mockGetAlerts.mockResolvedValue({ data: { alerts: [], total: 0 } })
    renderAlerts()

    expect(await screen.findByText(/no alerts match/i)).toBeInTheDocument()
  })

  it('renders severity filter dropdown', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const severitySelect = screen.getByDisplayValue('All severities')
    expect(severitySelect).toBeInTheDocument()
  })

  it('renders status filter dropdown', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const statusSelect = screen.getByDisplayValue('All statuses')
    expect(statusSelect).toBeInTheDocument()
  })

  it('calls getAlerts with filter params when severity filter changes', async () => {
    const user = userEvent.setup()
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const severitySelect = screen.getByDisplayValue('All severities')
    await user.selectOptions(severitySelect, 'critical')

    await waitFor(() => {
      expect(mockGetAlerts).toHaveBeenCalledWith(
        expect.objectContaining({ severity: 'critical' }),
      )
    })
  })

  it('calls getAlerts with filter params when status filter changes', async () => {
    const user = userEvent.setup()
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const statusSelect = screen.getByDisplayValue('All statuses')
    await user.selectOptions(statusSelect, 'new')

    await waitFor(() => {
      expect(mockGetAlerts).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'new' }),
      )
    })
  })

  it('shows Acknowledge button only for "new" alerts', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const ackButtons = screen.getAllByRole('button', { name: /acknowledge/i })
    expect(ackButtons).toHaveLength(1)
  })

  it('calls acknowledge API when Acknowledge button is clicked', async () => {
    const user = userEvent.setup()
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const ackButton = screen.getByRole('button', { name: /acknowledge/i })
    await user.click(ackButton)

    await waitFor(() => {
      expect(mockAcknowledge).toHaveBeenCalledWith('alert-1')
    })
  })

  it('shows Resolve button for new and acknowledged alerts', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const resolveButtons = screen.getAllByRole('button', { name: /resolve/i })
    expect(resolveButtons).toHaveLength(2)
  })

  it('calls resolve API when Resolve button is clicked', async () => {
    const user = userEvent.setup()
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const resolveButtons = screen.getAllByRole('button', { name: /resolve/i })
    await user.click(resolveButtons[0])

    await waitFor(() => {
      expect(mockResolve).toHaveBeenCalledWith('alert-1')
    })
  })

  it('calls ignore API when Ignore button is clicked', async () => {
    const user = userEvent.setup()
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const ignoreButton = screen.getByRole('button', { name: /ignore/i })
    await user.click(ignoreButton)

    await waitFor(() => {
      expect(mockIgnore).toHaveBeenCalledWith('alert-1')
    })
  })

  it('does not show action buttons for resolved alerts', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const rows = screen.getAllByRole('row')
    const bruteForceRow = rows.find((row) => within(row).queryByText('Brute Force'))
    expect(bruteForceRow).toBeTruthy()

    const buttons = within(bruteForceRow!).queryAllByRole('button')
    expect(buttons).toHaveLength(0)
  })

  it('renders table column headers', async () => {
    renderAlerts()
    await screen.findByText('DDoS Attack')

    const table = screen.getByRole('table')
    expect(within(table).getByText('Severity')).toBeInTheDocument()
    expect(within(table).getByText('Type')).toBeInTheDocument()
    expect(within(table).getByText('Source')).toBeInTheDocument()
    expect(within(table).getByText('Description')).toBeInTheDocument()
    expect(within(table).getByText('Time')).toBeInTheDocument()
    expect(within(table).getByText('Status')).toBeInTheDocument()
    expect(within(table).getByText('Actions')).toBeInTheDocument()
  })
})
