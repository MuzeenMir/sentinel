import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { LoadingSpinner } from './LoadingSpinner'

describe('LoadingSpinner', () => {
  it('renders without crashing', () => {
    render(<LoadingSpinner />)
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toBeInTheDocument()
  })

  it('applies size class for sm', () => {
    render(<LoadingSpinner size="sm" />)
    const spinner = document.querySelector('.w-4.h-4')
    expect(spinner).toBeInTheDocument()
  })

  it('applies size class for md by default', () => {
    render(<LoadingSpinner />)
    const spinner = document.querySelector('.w-8.h-8')
    expect(spinner).toBeInTheDocument()
  })

  it('applies size class for lg', () => {
    render(<LoadingSpinner size="lg" />)
    const spinner = document.querySelector('.w-12.h-12')
    expect(spinner).toBeInTheDocument()
  })

  it('applies custom className', () => {
    const { container } = render(<LoadingSpinner className="custom-class" />)
    const wrapper = container.firstChild
    expect(wrapper).toHaveClass('custom-class')
  })
})
