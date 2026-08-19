import { AlertTriangle, Check, Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * Étapes du pipeline. L'état de chaque étape provient de
 * `status.stage_report.stage_status` (backend) : plus aucune déduction à partir
 * du pourcentage de progression, contrairement à l'ancienne interface.
 */
export function StageTimeline({ stages, currentIndex, terminal }) {
  const stopped = terminal === 'stopped' || terminal === 'failed' || terminal === 'error'

  return (
    <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {stages.map((s, i) => {
        const done = s.status === 'completed' || (terminal === 'completed' && s.status !== 'failed')
        const active = !stopped && !done && (s.status === 'active' || i === currentIndex)
        const failed = stopped && i === currentIndex
        return (
          <li
            key={s.key}
            className={cn(
              'relative rounded-xl border p-4 transition-colors',
              failed
                ? 'border-critical/40 bg-critical/5'
                : active
                  ? 'border-primary/60 bg-primary/5'
                  : done
                    ? 'border-success/40 bg-success/5'
                    : 'border-border bg-card/40',
            )}
          >
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  'grid h-6 w-6 shrink-0 place-items-center rounded-full text-[11px] font-semibold',
                  failed
                    ? 'bg-critical text-critical-foreground'
                    : done
                      ? 'bg-success text-success-foreground'
                      : active
                        ? 'bg-primary text-primary-foreground'
                        : 'bg-muted text-muted-foreground ring-1 ring-border',
                )}
              >
                {failed ? (
                  <AlertTriangle className="h-3.5 w-3.5" />
                ) : done ? (
                  <Check className="h-3.5 w-3.5" />
                ) : active ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  i + 1
                )}
              </span>
              <div className="text-sm font-medium">{s.label}</div>
            </div>
            <div className="mt-2 text-xs text-muted-foreground">{s.description}</div>
          </li>
        )
      })}
    </ol>
  )
}
