import { Link, useLocation } from 'react-router-dom'

const navItems = [
  { path: '/scan', label: 'Setup & Scope' },
  { path: '/scan/connect', label: 'AWS Session Connector' },
  { path: '/scan/threats', label: 'Threat Workspace' },
  { path: '/graph', label: 'Topology Graph' },
]


interface LayoutProps {
  children: React.ReactNode
  breadcrumbs?: string[]
  scanId?: string
}

export default function Layout({ children, breadcrumbs = [], scanId }: LayoutProps) {
  const location = useLocation()

  return (
    <div className="flex h-screen bg-[#111111] text-[#e8e8e8] overflow-hidden">
      {/* Sidebar */}
      <aside className="w-52 border-r border-[#1e1e2e] bg-[#0e0e16] flex flex-col shrink-0">
        <div className="px-4 py-4 border-b border-[#1e1e2e]">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="grid h-7 w-7 place-items-center rounded bg-[#1e1b4b] border border-[#3730a3]/40 text-[10px] font-black text-[#a5b4fc]">
              BB
            </span>
            <div>
              <div className="text-sm font-semibold text-white tracking-wide">BREAKBOT</div>
              <div className="text-[10px] text-[#4b5563]">Workspace v1.2</div>
            </div>
          </Link>
        </div>

        <nav className="flex-1 px-2 py-3 overflow-y-auto">
          <div className="text-[10px] font-semibold uppercase tracking-[0.15em] text-[#374151] px-2 mb-2">
            Operational Directory
          </div>
          {navItems.map((item) => {
            const isActive = location.pathname.startsWith(item.path)
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center px-2 py-2 rounded text-sm mb-0.5 transition-colors ${
                  isActive
                    ? 'bg-[#1e1b4b]/60 text-[#a5b4fc] border border-[#3730a3]/30'
                    : 'text-[#6b7280] hover:text-[#d1d5db] hover:bg-[#16162a]'
                }`}
              >
                <span className="leading-none">{item.label}</span>
              </Link>
            )
          })}
        </nav>

        <div className="px-4 py-3 border-t border-[#1e1e2e] text-[11px] text-[#374151] space-y-0.5">
          <div>Security Model: <span className="text-[#777]">Read-Only</span></div>
          {scanId && <div>Scope Account: <span className="text-[#777] font-mono">{scanId}</span></div>}
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="flex items-center justify-between px-6 py-2.5 border-b border-[#1a1a2e] bg-[#111111] shrink-0">
          <div className="flex items-center gap-1.5 text-xs text-[#555]">
            <span>Workspace</span>
            {breadcrumbs.map((crumb, i) => (
              <span key={i} className="flex items-center gap-1.5">
                <span className="text-[#333]">/</span>
                <span className={i === breadcrumbs.length - 1 ? 'text-[#aaa] font-medium uppercase tracking-wide' : 'text-[#555]'}>
                  {crumb}
                </span>
              </span>
            ))}
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="text-[#444]">Documentation</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80]" />
              <span className="text-[#4ade80]">API Operational</span>
            </span>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8">
          <div className="mx-auto max-w-5xl">
            {children}
          </div>
        </div>
      </main>
    </div>
  )
}
