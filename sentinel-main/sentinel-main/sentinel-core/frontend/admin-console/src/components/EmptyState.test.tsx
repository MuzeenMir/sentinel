import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { EmptyState } from './EmptyState'

describe('EmptyState', () => {
  it('renders title', () => {
    render(<EmptyState title="No threats found" />)
    expect(screen.getByText('No threats found')).toBeInTheDocument()
  })

  it('renders description when provided', () => {
    render(
      <EmptyState
        title="No data"
        description="There are no items to display."
      />
    )
    expect(screen.getByText('There are no items to display.')).toBeInTheDocument()
  })

  it('renders default icon', () => {
    const { container } = render(<EmptyState title="Empty" />)
    expect(container.textContent).toContain('📭')
  })

  it('renders custom icon', () => {
    const { container } = render(<EmptyState title="Empty" icon="🔒" />)
    expect(container.textContent).toContain('🔒')
  })

  it('renders action button and calls onClick when clicked', () => {
    const onClick = vi.fn()
    render(
      <EmptyState
        title="No data"
        action={{ label: 'Refresh', onClick }}
      />
    )
    const button = screen.getByRole('button', { name: 'Refresh' })
    expect(button).toBeInTheDocument()
    fireEvent.click(button)
    expect(onClick).toHaveBeenCalledTimes(1)
  })
})
