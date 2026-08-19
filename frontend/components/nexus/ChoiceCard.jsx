import { Check } from 'lucide-react'
import { cn } from '@/lib/utils'

export function ChoiceCard({ selected, onClick, icon: Icon, title, tagline, bullets = [], badge }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'group relative w-full rounded-xl border p-5 text-left transition-all',
        selected
          ? 'border-primary/60 bg-primary/5 ring-glow'
          : 'border-border bg-card/50 hover:border-border/80 hover:bg-card',
      )}
    >
      <div className="flex items-start justify-between">
        <div className="grid h-10 w-10 place-items-center rounded-lg bg-gradient-to-br from-primary/30 to-primary/5 ring-1 ring-primary/30">
          <Icon className="h-5 w-5 text-primary" />
        </div>
        {badge && (
          <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wider text-muted-foreground ring-1 ring-border">
            {badge}
          </span>
        )}
        {selected && (
          <span className="absolute right-3 top-3 grid h-5 w-5 place-items-center rounded-full bg-primary text-primary-foreground">
            <Check className="h-3 w-3" />
          </span>
        )}
      </div>
      <div className="mt-3 text-base font-semibold">{title}</div>
      <div className="text-xs text-muted-foreground">{tagline}</div>
      <ul className="mt-3 space-y-1.5 text-xs text-muted-foreground/90">
        {bullets.map((b) => (
          <li key={b} className="flex items-start gap-1.5">
            <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-primary/70" />
            <span>{b}</span>
          </li>
        ))}
      </ul>
    </button>
  )
}
