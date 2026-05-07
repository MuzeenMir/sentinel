import { useState } from "react";
import { NavLink, useNavigate, useLocation, Link } from "react-router-dom";
import {
  LayoutDashboard,
  Shield,
  Bell,
  FileText,
  CheckCircle,
  Lock,
  Eye,
  Users,
  ClipboardList,
  Settings,
  Menu,
  X,
  Search,
  LogOut,
  ChevronDown,
  Building2,
  ShieldCheck,
  Plug,
} from "lucide-react";
import { useAuthStore } from "../store/authStore";

const navigation = [
  { name: "Dashboard", to: "/", icon: LayoutDashboard },
  { name: "Threats", to: "/threats", icon: Shield },
  { name: "Alerts", to: "/alerts", icon: Bell },
  { name: "Policies", to: "/policies", icon: FileText },
  { name: "Compliance", to: "/compliance", icon: CheckCircle },
  { name: "Hardening", to: "/hardening", icon: Lock },
  { name: "HIDS", to: "/hids", icon: Eye },
  { name: "Users", to: "/users", icon: Users },
  { name: "Audit Log", to: "/audit", icon: ClipboardList },
  { name: "Tenants", to: "/tenants", icon: Building2 },
  { name: "MFA Setup", to: "/mfa-setup", icon: ShieldCheck },
  { name: "SIEM / Integrations", to: "/siem", icon: Plug },
  { name: "Settings", to: "/settings", icon: Settings },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const activeNav = navigation.find((n) =>
    n.to === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(n.to),
  );

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 transform bg-slate-900 border-r border-slate-800 transition-transform duration-200 lg:static lg:translate-x-0 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center gap-3 px-6 border-b border-slate-800">
          <Shield className="h-8 w-8 text-cyan-400" />
          <div>
            <h1 className="text-lg font-bold tracking-wider text-white">
              SENTINEL
            </h1>
            <p className="text-[10px] text-slate-500 uppercase tracking-widest">
              Security Platform
            </p>
          </div>
          <button
            className="ml-auto lg:hidden text-slate-400 hover:text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
          {navigation.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                }`
              }
            >
              <item.icon className="h-[18px] w-[18px] flex-shrink-0" />
              {item.name}
            </NavLink>
          ))}
        </nav>
      </aside>

      <div className="flex flex-1 flex-col overflow-hidden">
        <header className="flex h-16 items-center gap-4 border-b border-slate-800 bg-slate-900/50 px-6">
          <button
            className="lg:hidden text-slate-400 hover:text-white"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="h-5 w-5" />
          </button>

          <div className="flex flex-1 items-center gap-3">
            {activeNav && (
              <span className="text-sm font-semibold text-slate-200">
                {activeNav.name}
              </span>
            )}
            <div className="relative max-w-md flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search threats, alerts, policies…"
                className="w-full rounded-lg border border-slate-700 bg-slate-800/50 py-2 pl-10 pr-4 text-sm text-slate-300 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          </div>

          <button className="relative text-slate-400 hover:text-white">
            <Bell className="h-5 w-5" />
            <span className="absolute -right-1 -top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
              3
            </span>
          </button>

          <div className="relative">
            <button
              aria-label="User menu"
              aria-haspopup="menu"
              aria-expanded={userMenuOpen}
              className="flex items-center gap-2 text-sm text-slate-300 hover:text-white"
              onClick={() => setUserMenuOpen(!userMenuOpen)}
            >
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-600 text-xs font-bold text-white">
                {user?.username?.charAt(0).toUpperCase() ?? "U"}
              </div>
              <span className="hidden sm:inline">
                {user?.username ?? "User"}
              </span>
              <ChevronDown className="h-4 w-4" />
            </button>

            {userMenuOpen && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setUserMenuOpen(false)}
                />
                <div
                  role="menu"
                  className="absolute right-0 z-50 mt-2 w-48 rounded-lg border border-slate-700 bg-slate-800 py-1 shadow-xl"
                >
                  <div className="px-4 py-2 border-b border-slate-700">
                    <p className="text-sm font-medium text-white">
                      {user?.username}
                    </p>
                    <p className="text-xs text-slate-400">{user?.role}</p>
                  </div>
                  <Link
                    to="/settings"
                    role="menuitem"
                    onClick={() => setUserMenuOpen(false)}
                    className="flex w-full items-center gap-2 px-4 py-2 text-sm text-slate-200 hover:bg-slate-700"
                  >
                    <Settings className="h-4 w-4" />
                    Settings
                  </Link>
                  <button
                    onClick={handleLogout}
                    role="menuitem"
                    className="flex w-full items-center gap-2 px-4 py-2 text-sm text-red-400 hover:bg-slate-700"
                  >
                    <LogOut className="h-4 w-4" />
                    Log out
                  </button>
                </div>
              </>
            )}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto bg-slate-950 p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
