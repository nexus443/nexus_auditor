import { cn } from '@/lib/utils'

/** État vide générique, aligné sur le design system de la nouvelle interface. */
export function EmptyState({ icon: Icon, title, description, action, className, tone = 'default' }) {
  const toneRing = {
    default: 'ring-border text-muted-foreground',
    success: 'ring-success/30 text-success',
    critical: 'ring-critical/30 text-critical',
  }[tone]

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card/30 px-6 py-14 text-center',
        className,
      )}
    >
      {Icon && (
        <div className={cn('mb-4 grid h-14 w-14 place-items-center rounded-full bg-muted ring-1', toneRing)}>
          <Icon className="h-6 w-6" />
        </div>
      )}
      <div className="text-base font-semibold">{title}</div>
      {description && (
        <p className="mt-1.5 max-w-md text-sm text-muted-foreground">{description}</p>
      )}
      {action && <div className="mt-5 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  )
}
