export function ScoreRing({ score, size = 140, label = 'Score', suffix = '' }) {
  // `score === null` = valeur non calculée (audit interrompu) : on affiche un
  // anneau vide avec « — » plutôt qu'un faux 0.
  const hasScore = score !== null && score !== undefined && Number.isFinite(Number(score))
  const safeScore = hasScore ? Math.max(0, Math.min(100, Number(score))) : 0
  const r = (size - 16) / 2
  const c = 2 * Math.PI * r
  const off = hasScore ? c - (safeScore / 100) * c : c
  const tone = safeScore >= 80 ? 'var(--success)' : safeScore >= 60 ? 'var(--medium)' : 'var(--critical)'
  return (
    <div className="relative grid shrink-0 place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="var(--muted)" strokeWidth={10} fill="none" />
        {hasScore && (
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            stroke={tone}
            strokeWidth={10}
            strokeLinecap="round"
            strokeDasharray={c}
            strokeDashoffset={off}
            fill="none"
            style={{ transition: 'stroke-dashoffset 600ms ease' }}
          />
        )}
      </svg>
      <div className="absolute text-center">
        <div className="text-3xl font-semibold tracking-tight">
          {hasScore ? (
            <>
              {Math.round(safeScore)}
              {suffix}
            </>
          ) : (
            '—'
          )}
        </div>
        <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      </div>
    </div>
  )
}
