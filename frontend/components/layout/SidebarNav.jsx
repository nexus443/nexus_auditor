import { NavLink } from 'react-router-dom'
import {
  Activity,
  FileText,
  History,
  LayoutDashboard,
  ListChecks,
  ScanSearch,
  Settings,
  ShieldCheck,
} from 'lucide-react'

import { cn } from '@/lib/utils'
import { useNexus } from '@/hooks/useNexus.jsx'

export const NAV_ITEMS = [
  { to: '/', label: 'Tableau de bord', icon: LayoutDashboard, end: true },
  { to: '/scan/new', label: 'Nouveau scan', icon: ScanSearch },
  { to: '/scan/live', label: 'Scan en direct', icon: Activity },
  { to: '/results', label: 'Résultats', icon: ListChecks },
  { to: '/history', label: 'Historique', icon: History },
  { to: '/reports', label: 'Rapports', icon: FileText },
  { to: '/settings', label: 'Paramètres', icon: Settings },
]

/** Contenu de la barre latérale, partagé entre le rail desktop et le tiroir mobile. */
export function SidebarNav({ onNavigate }) {
  const { isScanning, runtime, health, findings } = useNexus()
  const ollama = runtime.data?.ollama_context
  const reachable = Boolean(ollama?.reachable)

  const badges = {
    '/results': findings.length || null,
  }

  return (
    <>
      <div className="flex h-16 items-center gap-2.5 border-b border-sidebar-border px-5">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-gradient-to-br from-primary/30 to-primary/5 ring-1 ring-primary/40">
          <ShieldCheck className="h-5 w-5 text-primary" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">Nexus Auditor</div>
          <div className="text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground">
            Local-first AI Audit
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-4">
        <div className="px-2 pb-2 text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground">
          Workspace
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon
          const badge = badges[item.to]
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  'group flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-sidebar-accent text-sidebar-accent-foreground ring-1 ring-border'
                    : 'text-sidebar-foreground/80 hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={cn(
                      'h-4 w-4 shrink-0',
                      isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground',
                    )}
                  />
                  <span className="flex-1">{item.label}</span>
                  {item.to === '/scan/live' && isScanning && (
                    <span className="relative flex h-2 w-2">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success/60" />
                      <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
                    </span>
                  )}
                  {badge ? (
                    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground ring-1 ring-border">
                      {badge}
                    </span>
                  ) : null}
                </>
              )}
            </NavLink>
          )
        })}
      </nav>

      <div className="m-3 rounded-lg border border-border bg-card/60 p-3">
        <div className="flex items-center gap-2 text-xs">
          <span
            className={cn(
              'h-2 w-2 shrink-0 rounded-full',
              health.api === 'offline'
                ? 'bg-critical'
                : reachable
                  ? 'bg-success animate-pulse'
                  : runtime.loading
                    ? 'bg-muted-foreground'
                    : 'bg-high',
            )}
          />
          <span className="font-medium">
            {health.api === 'offline'
              ? 'API hors ligne'
              : runtime.loading
                ? 'Vérification…'
                : reachable
                  ? 'Ollama en ligne'
                  : 'Ollama injoignable'}
          </span>
        </div>
        <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
          {ollama?.base_url || '—'}
        </div>
        <div className="mt-2 truncate text-[11px] text-muted-foreground">
          {ollama?.model || '—'}
          {runtime.data?.profile_effective?.profile_name
            ? ` · ${runtime.data.profile_effective.profile_name}`
            : ''}
        </div>
      </div>
    </>
  )
}
