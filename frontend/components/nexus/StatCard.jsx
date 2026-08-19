import { cn } from '@/lib/utils'

export function StatCard({ label, value, delta, icon: Icon, tone = 'default', hint, children }) {
  const toneRing = {
    default: 'ring-border',
    success: 'ring-success/30',
    critical: 'ring-critical/30',
    warning: 'ring-high/30',
    primary: 'ring-primary/30',
  }[tone]
  const toneIcon = {
    default: 'text-muted-foreground',
    success: 'text-success',
    critical: 'text-critical',
    warning: 'text-high',
    primary: 'text-primary',
  }[tone]
  return (
    <div className={cn('relative min-w-0 overflow-hidden rounded-xl border border-border bg-card/60 p-5 ring-1', toneRing)}>
      <div className="flex items-start justify-between">
        <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
        {Icon && <Icon className={cn('h-4 w-4', toneIcon)} />}
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight">{value}</div>
      {delta && <div className="mt-1 text-xs text-muted-foreground">{delta}</div>}
      {hint && <div className="mt-2 text-xs text-muted-foreground/80">{hint}</div>}
      {children}
      <div className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full bg-primary/10 blur-3xl" />
    </div>
  )
}
