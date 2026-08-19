import { cn } from '@/lib/utils'

const map = {
  completed: { label: 'Terminé', c: 'bg-success/15 text-success ring-success/30' },
  failed: { label: 'Échec', c: 'bg-critical/15 text-critical ring-critical/30' },
  running: { label: 'En cours', c: 'bg-primary/15 text-primary ring-primary/30' },
  stopped: { label: 'Arrêté', c: 'bg-muted text-muted-foreground ring-border' },
}

export function StatusPill({ status }) {
  const m = map[status] || map.stopped
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1', m.c)}>
      <span
        className={cn('h-1.5 w-1.5 rounded-full', status === 'running' && 'animate-pulse')}
        style={{ background: 'currentColor' }}
      />
      {m.label}
    </span>
  )
}
