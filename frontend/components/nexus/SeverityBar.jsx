const ORDER = ['critical', 'high', 'medium', 'low', 'info']

const LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Autres',
}

/**
 * Répartition des vulnérabilités par sévérité.
 * `counts` provient de `status.stats` (backend), jamais de données statiques.
 */
export function SeverityBar({ counts }) {
  const safeCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, ...(counts || {}) }
  const sum = ORDER.reduce((acc, key) => acc + (safeCounts[key] || 0), 0)
  const total = sum || 1

  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted">
        {sum > 0 &&
          ORDER.map((k) => (
            <div
              key={k}
              style={{ width: `${(safeCounts[k] / total) * 100}%`, background: `var(--${k})` }}
              title={`${LABELS[k]}: ${safeCounts[k]}`}
            />
          ))}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-3 lg:grid-cols-5">
        {ORDER.map((k) => (
          <div key={k} className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: `var(--${k})` }} />
            <span className="text-muted-foreground">{LABELS[k]}</span>
            <span className="ml-auto font-mono">{safeCounts[k]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
