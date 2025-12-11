import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, 
  ShieldAlert, 
  History, 
  Settings, 
  Scan,
  ChevronRight
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface AppLayoutProps {
  children: ReactNode
}

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Findings', href: '/findings', icon: ShieldAlert },
  { name: 'Remediation History', href: '/remediation-history', icon: History },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation()

  // Get current page title for breadcrumb
  const currentPage = navigation.find(item => item.href === location.pathname)
  const pageTitle = currentPage?.name || 'Dashboard'

  return (
    <div className="flex h-screen bg-aide-bg-primary">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-50 w-64 bg-aide-bg-secondary border-r border-aide-border-DEFAULT">
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center gap-3 px-6 py-5 border-b border-aide-border-DEFAULT">
            <div className="relative">
              <img 
                src="/aide-logo.svg" 
                alt="AIDE" 
                className="w-9 h-9"
              />
              <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-green-500 rounded-full border-2 border-aide-bg-secondary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-aide-text-primary tracking-tight">
                AIDE
              </h1>
              <p className="text-xs text-aide-text-muted">
                IAM Detection Engine
              </p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={cn(
                    isActive ? 'aide-nav-item-active' : 'aide-nav-item'
                  )}
                >
                  <item.icon className="w-5 h-5" />
                  <span>{item.name}</span>
                </Link>
              )
            })}
          </nav>

          {/* Footer */}
          <div className="px-3 py-4 border-t border-aide-border-DEFAULT">
            <div className="aide-card p-3">
              <div className="flex items-center gap-2 text-xs text-aide-text-muted">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                <span>System Status: Active</span>
              </div>
              <p className="mt-1.5 text-xxs text-aide-text-muted">
                Version 1.0.0
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64 flex flex-col min-h-screen">
        {/* Sticky Header */}
        <header className="sticky top-0 z-40 bg-aide-bg-primary/80 backdrop-blur-sm border-b border-aide-border-DEFAULT">
          <div className="flex items-center justify-between px-6 py-4">
            {/* Breadcrumb */}
            <div className="flex items-center gap-2 text-sm">
              <span className="text-aide-text-muted">Dashboard</span>
              {pageTitle !== 'Dashboard' && (
                <>
                  <ChevronRight className="w-4 h-4 text-aide-text-muted" />
                  <span className="text-aide-text-primary font-medium">{pageTitle}</span>
                </>
              )}
              {pageTitle === 'Dashboard' && (
                <>
                  <ChevronRight className="w-4 h-4 text-aide-text-muted" />
                  <span className="text-aide-text-primary font-medium">Overview</span>
                </>
              )}
            </div>

            {/* Actions */}
            <button className="aide-btn-primary">
              <Scan className="w-4 h-4" />
              Run New Scan
            </button>
          </div>
        </header>

        {/* Page Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6">
            {children}
          </div>
        </div>
      </main>
    </div>
  )
}
