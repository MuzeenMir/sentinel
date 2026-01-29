import { ReactNode, useState, useRef, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { clsx } from 'clsx'
import { appConfig } from '../config/runtime'
import { useAuthStore } from '../store/authStore'

interface LayoutProps {
  children: ReactNode
}

type IconProps = {
  className?: string
}

type NavItem = {
  name: string
  href: string
  Icon: (props: IconProps) => JSX.Element
}

const navigation: NavItem[] = [
  { name: 'Dashboard', href: '/', Icon: DashboardIcon },
  { name: 'Threats', href: '/threats', Icon: ThreatsIcon },
  { name: 'Policies', href: '/policies', Icon: PoliciesIcon },
  { name: 'Compliance', href: '/compliance', Icon: ComplianceIcon },
  { name: 'Settings', href: '/settings', Icon: SettingsIcon },
]

const isActiveRoute = (href: string, pathname: string) => {
  if (href === '/') {
    return pathname === '/'
  }
  return pathname.startsWith(href)
}

const formatEnvLabel = (env: string) => {
  if (env.toLowerCase() === 'production') {
    return 'PROD'
  }
  return env.toUpperCase()
}

function getInitials(name: string | undefined): string {
  if (!name || !name.trim()) return '?'
  const parts = name.trim().split(/\s+/)
  if (parts.length >= 2) {
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase().slice(0, 2)
  }
  return name.slice(0, 2).toUpperCase()
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation()
  const { user, logout } = useAuthStore()
  const [profileOpen, setProfileOpen] = useState(false)
  const profileRef = useRef<HTMLDivElement>(null)
  const activeItem = navigation.find((item) => isActiveRoute(item.href, location.pathname)) || navigation[0]
  const envLabel = formatEnvLabel(appConfig.appEnv)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setProfileOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="flex">
      {/* Sidebar */}
        <aside className="w-72 bg-slate-950/90 border-r border-slate-800/80 backdrop-blur">
          <div className="p-6">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-blue-600/20 text-blue-300 flex items-center justify-center font-semibold">
                S
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">
                  {appConfig.appName}
                </p>
                <p className="text-lg font-semibold text-slate-100">Security Platform</p>
              </div>
            </div>
          </div>

          <nav className="px-3 space-y-1">
            {navigation.map((item) => {
              const isActive = isActiveRoute(item.href, location.pathname)
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={clsx(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors border',
                    isActive
                      ? 'bg-blue-600/15 text-blue-300 border-blue-500/30'
                      : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-900/60 hover:border-slate-800/60'
                  )}
                >
                  <item.Icon className="h-5 w-5" />
                  {item.name}
                </Link>
              )
            })}
          </nav>

          <div className="mt-auto p-4 border-t border-slate-800/80" ref={profileRef}>
            <div
              role="button"
              tabIndex={0}
              onClick={() => setProfileOpen((o) => !o)}
              onKeyDown={(e) => e.key === 'Enter' && setProfileOpen((o) => !o)}
              className="flex items-center gap-3 rounded-lg px-2 py-1.5 cursor-pointer hover:bg-slate-800/60 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
              aria-expanded={profileOpen}
              aria-haspopup="true"
              aria-label="User menu"
            >
              <div className="h-9 w-9 rounded-full bg-slate-800 text-slate-200 flex items-center justify-center text-sm font-semibold shrink-0">
                {getInitials(user?.username)}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-100 truncate">{user?.username ?? 'User'}</p>
                <p className="text-xs text-slate-500 truncate">{user?.email ?? '—'}</p>
              </div>
              <span className="text-xs text-slate-500 shrink-0 capitalize">{user?.role ?? '—'}</span>
            </div>
            {profileOpen && (
              <div
                className="mt-2 py-1 rounded-lg border border-slate-800/80 bg-slate-900/95 shadow-lg"
                role="menu"
              >
                <Link
                  to="/settings"
                  className="block px-4 py-2 text-sm text-slate-300 hover:bg-slate-800/60 hover:text-slate-100"
                  role="menuitem"
                  onClick={() => setProfileOpen(false)}
                >
                  Settings
                </Link>
                <button
                  type="button"
                  onClick={() => {
                    setProfileOpen(false)
                    logout()
                  }}
                  className="w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-800/60 hover:text-slate-100"
                  role="menuitem"
                >
                  Log out
                </button>
              </div>
            )}
          </div>
        </aside>

      {/* Main content */}
        <main className="flex-1 min-h-screen">
          <header className="sticky top-0 z-10 bg-slate-950/80 border-b border-slate-800/80 backdrop-blur">
            <div className="px-6 py-4 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Workspace</p>
                <h2 className="text-lg font-semibold text-slate-100">{activeItem.name}</h2>
              </div>
              <div className="flex flex-col gap-3 md:flex-row md:items-center">
                <div className="relative md:w-72">
                  <input
                    type="search"
                    placeholder="Search threats, policies, IPs"
                    className="w-full rounded-lg border border-slate-800/80 bg-slate-900/60 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
                  />
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-300">
                  <span className="inline-flex items-center gap-2 rounded-full border border-slate-800/80 bg-slate-900/70 px-2.5 py-1">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                    System Operational
                  </span>
                  <span className="inline-flex items-center rounded-full border border-slate-800/80 bg-slate-900/70 px-2.5 py-1">
                    {envLabel}
                  </span>
                </div>
              </div>
            </div>
          </header>

          <div className="p-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

function DashboardIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  )
}

function ThreatsIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 3l7 3v6c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
      <path d="M9.5 12.5l1.5 1.5 3.5-3.5" />
    </svg>
  )
}

function PoliciesIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" />
      <path d="M14 3v5h5" />
      <path d="M9 13h6" />
      <path d="M9 17h6" />
    </svg>
  )
}

function ComplianceIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M9 12.5l2.5 2.5L17 9" />
      <path d="M12 3l7 3v6c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
    </svg>
  )
}

function SettingsIcon({ className }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z" />
      <path d="M4.5 12h2M17.5 12h2M7.1 7.1l1.4 1.4M15.5 15.5l1.4 1.4M15.5 8.5l1.4-1.4M7.1 16.9l1.4-1.4" />
    </svg>
  )
}
