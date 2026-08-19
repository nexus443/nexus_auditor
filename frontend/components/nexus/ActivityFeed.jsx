import { AlertTriangle, CheckCircle2, Info, ScanSearch, XCircle } from 'lucide-react'

import { logLevel } from '@/utils/mappers'

const ICONS = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  error: XCircle,
  finding: ScanSearch,
}

const TONES = {
  info: 'text-muted-foreground',
  success: 'text-success',
  warning: 'text-medium',
  error: 'text-critical',
  finding: 'text-primary',
}

/**
 * Activité récente : derniers événements réels du scan courant
 * (`status.logs`). La maquette utilisait une liste figée.
 */
export function ActivityFeed({ logs, limit = 8 }) {
  const recent = [...(logs || [])].slice(-limit).reverse()

  return (
    <div className="min-w-0 rounded-xl border border-border bg-card/60 p-5">
      <h3 className="text-sm font-semibold">Activité récente</h3>
      {recent.length === 0 ? (
        <p className="mt-4 text-sm text-muted-foreground">
          Aucun événement pour l'instant. Lancez un audit pour voir l'activité du moteur.
        </p>
      ) : (
        <ul className="mt-4 space-y-3">
          {recent.map((log, index) => {
            const level = logLevel(log)
            const Icon = ICONS[level] || Info
            return (
              <li key={`${log.time}-${index}`} className="flex items-start gap-3">
                <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md bg-muted ring-1 ring-border">
                  <Icon className={`h-3.5 w-3.5 ${TONES[level] || TONES.info}`} />
                </div>
                <div className="min-w-0">
                  <div className="text-sm break-words">{log.msg}</div>
                  <div className="text-[11px] text-muted-foreground font-mono">{log.time}</div>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
