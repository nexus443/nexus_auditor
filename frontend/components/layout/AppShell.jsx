import { Outlet } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'

import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'
import { useNexus } from '@/hooks/useNexus.jsx'

export function AppShell() {
  const { health } = useNexus()

  return (
    <div className="flex min-h-screen w-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        {health.api === 'offline' && (
          <div className="flex items-center gap-2 border-b border-critical/30 bg-critical/10 px-4 py-2 text-xs text-critical md:px-8">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            Backend injoignable — les données affichées peuvent être obsolètes.
          </div>
        )}
        <main className="flex-1 px-4 md:px-8 py-6 md:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
