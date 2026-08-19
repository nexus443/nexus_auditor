import { cn } from '@/lib/utils'

const styles = {
  critical: 'bg-critical/15 text-critical ring-critical/30',
  high: 'bg-high/15 text-high ring-high/30',
  medium: 'bg-medium/15 text-medium ring-medium/30',
  low: 'bg-low/15 text-low ring-low/30',
  info: 'bg-info/15 text-info ring-info/30',
}

export function SeverityBadge({ severity, label, className }) {
  const key = styles[severity] ? severity : 'info'
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ring-1',
        styles[key],
        className,
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: `var(--${key})` }} />
      {label || key}
    </span>
  )
}
