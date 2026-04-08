import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { Dashboard } from './Dashboard'

vi.mock('../services/stream', () => ({
  createSseClient: vi.fn(() => ({ close: vi.fn() })),
}))

vi.mock('recharts', () => {
  const FakeChart = ({ children }: { children?: React.ReactNode }) => <div data-testid="chart">{children}</div>
  return {
    LineChart: FakeChart,
    BarChart: FakeChart,
    Line: () => null,
    Bar: () => null,
    XAxis: () => null,
    YAxis: () => null,
    CartesianGrid: () => null,
    Tooltip: () => null,
    ResponsiveContainer: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  }
})

const mockGetDashboardStats = vi.fn()
const mockGetTrafficStats = vi.fn()

vi.mock('../services/api', () => ({
  statsApi: {
    getDashboardStats: (...args: unknown[]) => mockGetDashboardStats(...args),
    getTrafficStats: (...args: unknown[]) => mockGetTrafficStats(...args),
  },
}))

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

function renderDashboard() {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetDashboardStats.mockRejectedValue(new Error('offline'))
    mockGetTrafficStats.mockRejectedValue(new Error('offline'))
  })

  it('renders stat cards with fallback mock data when API is unavailable', async () => {
    renderDashboard()

    expect(screen.getByText('Total Threats')).toBeInTheDocument()
    expect(screen.getByText('Blocked Threats')).toBeInTheDocument()
    expect(screen.getByText('Active Policies')).toBeInTheDocument()
    expect(screen.getByText('Compliance Score')).toBeInTheDocument()

    expect(screen.getByText('1247')).toBeInTheDocument()
    expect(screen.getByText('1189')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('94%')).toBeInTheDocument()
  })

  it('renders section headings', () => {
    renderDashboard()

    expect(screen.getByText('Security Overview')).toBeInTheDocument()
    expect(screen.getByText('Network Traffic (24h)')).toBeInTheDocument()
    expect(screen.getByText('Threat Activity (24h)')).toBeInTheDocument()
    expect(screen.getByText('Recent Threats')).toBeInTheDocument()
  })

  it('renders recent threats table with mock data', () => {
    renderDashboard()

    expect(screen.getByText('DDoS Attack')).toBeInTheDocument()
    expect(screen.getByText('Port Scan')).toBeInTheDocument()
    expect(screen.getByText('Brute Force')).toBeInTheDocument()
    expect(screen.getByText('SQL Injection')).toBeInTheDocument()
  })

  it('shows fallback warning banner when API returns errors', async () => {
    renderDashboard()

    const banner = await screen.findByText(/live telemetry is unavailable/i, {}, { timeout: 3000 })
    expect(banner).toBeInTheDocument()
  })

  it('renders "View All" link pointing to /threats', () => {
    renderDashboard()

    const link = screen.getByRole('link', { name: /view all/i })
    expect(link).toHaveAttribute('href', '/threats')
  })

  it('shows stat cards with live data when API succeeds', async () => {
    mockGetDashboardStats.mockResolvedValue({
      data: {
        stats: {
          totalThreats: 500,
          blockedThreats: 490,
          activePolicies: 20,
          complianceScore: 99,
        },
        recentThreats: [],
      },
    })
    mockGetTrafficStats.mockResolvedValue({ data: [] })

    renderDashboard()

    expect(await screen.findByText('500')).toBeInTheDocument()
    expect(screen.getByText('490')).toBeInTheDocument()
    expect(screen.getByText('20')).toBeInTheDocument()
    expect(screen.getByText('99%')).toBeInTheDocument()
  })

  it('shows "No recent threats detected." when recentThreats is empty', async () => {
    mockGetDashboardStats.mockResolvedValue({
      data: { stats: {}, recentThreats: [] },
    })
    mockGetTrafficStats.mockResolvedValue({ data: [] })

    renderDashboard()

    expect(await screen.findByText(/no recent threats detected/i)).toBeInTheDocument()
  })

  it('opens SSE stream on mount and closes on unmount', async () => {
    const { createSseClient } = await import('../services/stream')
    const closeFn = vi.fn()
    vi.mocked(createSseClient).mockReturnValue({ close: closeFn } as unknown as EventSource)

    const { unmount } = renderDashboard()

    expect(createSseClient).toHaveBeenCalledWith('/api/v1/stream/alerts', expect.any(Function))

    unmount()
    expect(closeFn).toHaveBeenCalled()
  })

  it('renders Investigate links for each threat row', () => {
    renderDashboard()

    const investigateLinks = screen.getAllByRole('link', { name: /investigate/i })
    expect(investigateLinks.length).toBe(4)
  })
})
