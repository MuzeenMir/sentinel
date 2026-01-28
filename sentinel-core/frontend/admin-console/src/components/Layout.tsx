import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { clsx } from 'clsx'

interface LayoutProps {
  children: ReactNode
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: '📊' },
  { name: 'Threats', href: '/threats', icon: '🛡️' },
  { name: 'Policies', href: '/policies', icon: '📋' },
  { name: 'Compliance', href: '/compliance', icon: '✅' },
  { name: 'Settings', href: '/settings', icon: '⚙️' },
]

export function Layout({ children }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-800 border-r border-gray-700">
        <div className="p-6">
          <h1 className="text-2xl font-bold text-blue-500">SENTINEL</h1>
          <p className="text-sm text-gray-400">Security Platform</p>
        </div>
        
        <nav className="mt-6">
          {navigation.map((item) => (
            <Link
              key={item.name}
              to={item.href}
              className={clsx(
                'flex items-center gap-3 px-6 py-3 text-sm font-medium transition-colors',
                location.pathname === item.href
                  ? 'bg-blue-600/20 text-blue-400 border-r-2 border-blue-500'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-700/50'
              )}
            >
              <span>{item.icon}</span>
              {item.name}
            </Link>
          ))}
        </nav>
        
        <div className="absolute bottom-0 left-0 w-64 p-4 border-t border-gray-700">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white text-sm">
              S
            </div>
            <div>
              <p className="text-sm font-medium">Santa</p>
              <p className="text-xs text-gray-400">santa@sentinel.local</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">
              {navigation.find(n => n.href === location.pathname)?.name || 'Dashboard'}
            </h2>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm text-green-400">
                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                System Operational
              </div>
            </div>
          </div>
        </header>
        
        <div className="p-6">
          {children}
        </div>
      </main>
    </div>
  )
}
