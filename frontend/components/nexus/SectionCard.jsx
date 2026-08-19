import { cn } from '@/lib/utils'

export function SectionCard({ title, description, actions, children, className }) {
  return (
    <section className={cn('min-w-0 rounded-xl border border-border bg-card/60 p-5', className)}>
      {(title || actions) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            {title && <h3 className="text-sm font-semibold">{title}</h3>}
            {description && <p className="text-xs text-muted-foreground">{description}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  )
}
