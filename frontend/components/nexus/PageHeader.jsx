export function PageHeader({ eyebrow, title, description, actions }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-border pb-5">
      <div>
        {eyebrow && (
          <div className="mb-1.5 text-[11px] uppercase tracking-[0.18em] text-primary/80">{eyebrow}</div>
        )}
        <h1 className="text-2xl md:text-[28px] font-semibold tracking-tight text-gradient">{title}</h1>
        {description && (
          <p className="mt-1.5 max-w-2xl text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
