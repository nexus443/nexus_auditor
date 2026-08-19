import { Cpu, Gauge, Server } from 'lucide-react'

import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { formatSeconds } from '@/utils/format'

/**
 * État réel du runtime, alimenté par `GET /scan/preflight` :
 * endpoint Ollama résolu par le backend, joignabilité, modèle du profil,
 * modèles installés et budget effectif (contexte, concurrence, timeouts).
 *
 * La maquette affichait ici des valeurs figées (RTX 4090, VRAM 18.2/24 GB) :
 * le backend n'expose aucune télémétrie GPU, ces blocs sont donc remplacés par
 * les informations réellement disponibles.
 */
export function RuntimeStatus({ preflight, loading, error, apiHealth }) {
  const ollama = preflight?.ollama_context
  const budget = preflight?.profile_effective
  const reachable = Boolean(ollama?.reachable)

  const state = loading
    ? { label: 'Vérification…', cls: 'bg-muted text-muted-foreground ring-border', dot: 'bg-muted-foreground' }
    : error || apiHealth === 'offline'
      ? { label: 'API hors ligne', cls: 'bg-critical/15 text-critical ring-critical/30', dot: 'bg-critical' }
      : reachable
        ? { label: 'En ligne', cls: 'bg-success/15 text-success ring-success/30', dot: 'bg-success animate-pulse' }
        : { label: 'Injoignable', cls: 'bg-high/15 text-high ring-high/30', dot: 'bg-high' }

  return (
    <div className="min-w-0 rounded-xl border border-border bg-card/60 p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Server className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold">Runtime</h3>
        </div>
        <span
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1',
            state.cls,
          )}
        >
          <span className={cn('h-1.5 w-1.5 rounded-full', state.dot)} /> {state.label}
        </span>
      </div>

      {loading && !preflight ? (
        <div className="mt-4 space-y-2.5">
          {[0, 1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-5 w-full" />
          ))}
        </div>
      ) : error && !preflight ? (
        <p className="mt-4 text-xs text-muted-foreground">
          Runtime indisponible&nbsp;: {error}
        </p>
      ) : (
        <>
          <dl className="mt-4 space-y-2.5 text-sm">
            <Row label="Endpoint" value={<code className="text-xs">{ollama?.base_url || '—'}</code>} />
            <Row label="Connexion" value={<span className="text-xs">{ollama?.mode === 'remote' ? 'Distante' : 'Locale'}</span>} />
            <Row label="Modèle" value={<span className="font-mono text-xs">{ollama?.model || '—'}</span>} />
            <Row label="Profil" value={<span className="text-xs capitalize">{budget?.profile_name || '—'}</span>} />
          </dl>

          {budget && (
            <div className="mt-4 grid grid-cols-3 gap-2 text-center">
              <Mini label="Contexte" value={`${Math.round((budget.target_chunk_tokens || 0) / 1000)}k`} />
              <Mini label="Workers" value={String(budget.max_concurrency ?? '—')} />
              <Mini label="Timeout" value={formatSeconds(budget.read_timeout_s)} />
            </div>
          )}

          {ollama?.tags?.length > 0 && (
            <div className="mt-4">
              <div className="mb-1.5 flex items-center justify-between text-xs text-muted-foreground">
                <span className="inline-flex items-center gap-1.5">
                  <Gauge className="h-3.5 w-3.5" /> Modèles installés
                </span>
                <span className="font-mono">{ollama.tags.length}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {ollama.tags.slice(0, 6).map((tag) => (
                  <span
                    key={tag}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground ring-1 ring-border"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {preflight?.warnings?.length > 0 && (
            <ul className="mt-4 space-y-1 text-[11px] text-high">
              {preflight.warnings.map((warning) => (
                <li key={warning}>⚠ {warning}</li>
              ))}
            </ul>
          )}
        </>
      )}

      <div className="mt-4 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <Cpu className="h-3 w-3" /> Local-first · le code ne quitte pas votre infrastructure
      </div>
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate">{value}</dd>
    </div>
  )
}

function Mini({ label, value }) {
  return (
    <div className="rounded-md border border-border bg-background/40 p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </div>
  )
}
