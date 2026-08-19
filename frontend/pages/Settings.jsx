import { Check, Moon, RefreshCw, Sun } from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { SectionCard } from '@/components/nexus/SectionCard'
import { OllamaConnection } from '@/components/nexus/OllamaConnection'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { useNexus } from '@/hooks/useNexus.jsx'
import { cn } from '@/lib/utils'
import { formatBytes, formatNumber, formatSeconds } from '@/utils/format'

const PROFILE_KEYS = ['eco', 'balanced', 'elite', 'titan']
const MODE_KEYS = ['rapid', 'deep', 'devsecops']

/**
 * Paramètres de l'application.
 *
 * Toutes les valeurs modifiables ici sont des préférences réellement utilisées
 * par Nexus (cible par défaut, profil, mode, connexion Ollama, thème) et
 * persistées dans localStorage. Les blocs « Telemetry », « Auto-redact » et
 * « Request timeout » de la maquette n'ont pas d'équivalent configurable côté
 * backend : les valeurs effectives correspondantes sont affichées en lecture
 * seule à partir du preflight.
 */
export default function Settings() {
  const {
    theme,
    setTheme,
    target,
    setTarget,
    profile,
    setProfile,
    scanMode,
    setScanMode,
    catalog,
    runtime,
    refreshRuntime,
  } = useNexus()

  const budget = runtime.data?.profile_effective
  const ollama = runtime.data?.ollama_context

  return (
    <>
      <PageHeader
        eyebrow="Configuration"
        title="Paramètres"
        description="Runtime d'inférence, profil de puissance, mode d'analyse et préférences d'affichage."
        actions={
          <Button variant="outline" className="gap-1.5" onClick={refreshRuntime} disabled={runtime.loading}>
            <RefreshCw className={cn('h-4 w-4', runtime.loading && 'animate-spin')} /> Rafraîchir
          </Button>
        }
      />

      <div className="grid gap-5 xl:grid-cols-2">
        <SectionCard title="Runtime" description="Point d'accès d'inférence utilisé par le backend.">
          <OllamaConnection />

          <div className="mt-5 space-y-2 border-t border-border pt-4 text-sm">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
              Valeurs effectives (preflight)
            </div>
            {runtime.loading && !runtime.data ? (
              <div className="space-y-2">
                {[0, 1, 2].map((i) => (
                  <Skeleton key={i} className="h-5 w-full" />
                ))}
              </div>
            ) : runtime.error && !runtime.data ? (
              <p className="text-xs text-muted-foreground">{runtime.error}</p>
            ) : (
              <dl className="space-y-2">
                <Row label="Endpoint résolu" value={<code className="text-xs">{ollama?.base_url || '—'}</code>} />
                <Row label="Modèle du profil" value={<span className="font-mono text-xs">{ollama?.model || '—'}</span>} />
                <Row
                  label="Timeout lecture"
                  value={<span className="text-xs">{formatSeconds(budget?.read_timeout_s)}</span>}
                />
                <Row
                  label="Timeout connexion"
                  value={<span className="text-xs">{formatSeconds(budget?.connect_timeout_s)}</span>}
                />
                <Row
                  label="Budget global"
                  value={<span className="text-xs">{formatSeconds(budget?.global_scan_timeout_s)}</span>}
                />
                <Row
                  label="Concurrence"
                  value={<span className="text-xs">{budget?.max_concurrency ?? '—'} worker(s)</span>}
                />
                <Row
                  label="Preuve stricte"
                  value={
                    <span className="text-xs">
                      {budget?.strict_evidence ? 'Activée' : 'Désactivée'}
                    </span>
                  }
                />
              </dl>
            )}
          </div>
        </SectionCard>

        <SectionCard title="Modèles installés" description="Modèles détectés sur le runtime Ollama.">
          {runtime.loading && !runtime.data ? (
            <div className="space-y-2">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-14 w-full" />
              ))}
            </div>
          ) : !ollama?.tags?.length ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              {ollama?.reachable
                ? 'Aucun modèle détecté sur ce runtime.'
                : "Runtime injoignable : impossible de lister les modèles."}
            </p>
          ) : (
            <div className="space-y-2">
              {ollama.tags.map((tag) => (
                <div
                  key={tag}
                  className={cn(
                    'flex w-full items-center justify-between rounded-lg border p-3 text-left',
                    tag === ollama.model
                      ? 'border-primary/60 bg-primary/5'
                      : 'border-border bg-background/40',
                  )}
                >
                  <div className="font-mono text-sm">{tag}</div>
                  {tag === ollama.model && (
                    <span className="inline-flex items-center gap-1.5 text-xs text-primary">
                      <Check className="h-4 w-4" /> Utilisé par le profil {budget?.profile_name}
                    </span>
                  )}
                </div>
              ))}
              <p className="pt-1 text-xs text-muted-foreground">
                Le modèle est déterminé par le profil de puissance : il se change en changeant de profil.
              </p>
            </div>
          )}
        </SectionCard>

        <SectionCard
          title="Profil de puissance par défaut"
          description="Budget matériel appliqué aux prochains audits."
        >
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {PROFILE_KEYS.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setProfile(key)}
                title={catalog.profiles?.[key]?.description || ''}
                className={cn(
                  'rounded-lg border p-3 text-sm capitalize transition-colors',
                  profile === key
                    ? 'border-primary/60 bg-primary/5 text-foreground'
                    : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
                )}
              >
                {key}
              </button>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            Sélection : <span className="text-foreground">{catalog.profiles?.[profile]?.label || profile}</span>
            {catalog.profiles?.[profile]?.description ? ` — ${catalog.profiles[profile].description}` : ''}
          </p>
        </SectionCard>

        <SectionCard title="Mode d'analyse par défaut" description="Profondeur sémantique des prochains audits.">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {MODE_KEYS.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => setScanMode(key)}
                title={catalog.modes?.[key]?.description || ''}
                className={cn(
                  'rounded-lg border p-3 text-sm capitalize transition-colors',
                  scanMode === key
                    ? 'border-primary/60 bg-primary/5 text-foreground'
                    : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
                )}
              >
                {key}
              </button>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            Sélection : <span className="text-foreground">{catalog.modes?.[scanMode]?.label || scanMode}</span>
            {catalog.modes?.[scanMode]?.description ? ` — ${catalog.modes[scanMode].description}` : ''}
          </p>
        </SectionCard>

        <SectionCard title="Cible par défaut" description="Pré-remplie à l'ouverture de l'assistant d'audit.">
          <Label className="text-xs uppercase tracking-wider text-muted-foreground">
            Dépôt ou chemin
          </Label>
          <Input
            className="mt-2 font-mono text-sm"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="https://github.com/company/repo.git ou /chemin/local"
          />
          {runtime.data?.repo_stats && (
            <p className="mt-3 text-xs text-muted-foreground">
              Dernier preflight : {formatNumber(runtime.data.repo_stats.analyzable_files)} fichier(s)
              analysable(s) sur {formatNumber(runtime.data.repo_stats.total_files)} ·{' '}
              {formatBytes(runtime.data.repo_stats.total_bytes_est)}
            </p>
          )}
        </SectionCard>

        <SectionCard title="Apparence" description="Préférence enregistrée sur ce navigateur.">
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setTheme('dark')}
              className={cn(
                'flex items-center justify-center gap-2 rounded-lg border p-3 text-sm transition-colors',
                theme === 'dark'
                  ? 'border-primary/60 bg-primary/5 text-foreground'
                  : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
              )}
            >
              <Moon className="h-4 w-4" /> Sombre
            </button>
            <button
              type="button"
              onClick={() => setTheme('light')}
              className={cn(
                'flex items-center justify-center gap-2 rounded-lg border p-3 text-sm transition-colors',
                theme === 'light'
                  ? 'border-primary/60 bg-primary/5 text-foreground'
                  : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
              )}
            >
              <Sun className="h-4 w-4" /> Clair
            </button>
          </div>
        </SectionCard>
      </div>

      <p className="mt-6 text-xs text-muted-foreground">
        Les préférences sont enregistrées automatiquement dans ce navigateur. La configuration
        moteur (seuils de confiance, budgets LLM, exclusions) reste pilotée par le backend.
      </p>
    </>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate text-right">{value}</dd>
    </div>
  )
}
