import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  Cpu,
  FileCode2,
  Flame,
  FolderGit2,
  Gauge,
  GitBranch,
  Leaf,
  Loader2,
  Rocket,
  ShieldCheck,
  Sparkles,
  Zap,
} from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { SectionCard } from '@/components/nexus/SectionCard'
import { ChoiceCard } from '@/components/nexus/ChoiceCard'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { OllamaConnection } from '@/components/nexus/OllamaConnection'
import { useNexus } from '@/hooks/useNexus.jsx'
import { usePreflight } from '@/hooks/usePreflight'
import { cn } from '@/lib/utils'
import { formatBytes, formatNumber, formatSeconds } from '@/utils/format'

/**
 * Modes et profils exposés par le backend (`SCAN_MODES`, `POWER_PROFILES`).
 * Les libellés et descriptions proviennent de `/modes` et `/profiles` quand
 * l'API répond ; les puces décrivent les seuils réels appliqués par le moteur.
 */
const MODES = [
  {
    key: 'rapid',
    icon: Zap,
    fallbackLabel: 'Scan Rapide',
    fallbackDescription: 'Critique uniquement',
    bullets: ['Sévérité High et plus', 'Confiance ≥ 50 %', '30 fichiers max, 20 s/fichier'],
  },
  {
    key: 'deep',
    icon: ShieldCheck,
    fallbackLabel: 'Scan Profond',
    fallbackDescription: 'Audit standard entreprise',
    bullets: ['Sévérité Medium et plus', 'Confiance ≥ 35 %', 'Corrélation inter-fichiers'],
  },
  {
    key: 'devsecops',
    icon: GitBranch,
    fallbackLabel: 'DevSecOps',
    fallbackDescription: 'Exhaustivité maximale',
    bullets: ['Toutes sévérités', 'Confiance ≥ 30 %', 'Config, IaC et scripts inclus'],
  },
]

const PROFILES = [
  {
    key: 'eco',
    icon: Leaf,
    fallbackLabel: '🍃 Eco',
    fallbackDescription: 'Stabilité maximale (Low Ram)',
    bullets: ['qwen2.5-coder:7b', 'Contexte 8k', '1 fichier en parallèle'],
  },
  {
    key: 'balanced',
    icon: Gauge,
    fallbackLabel: '⚖️ Balanced',
    fallbackDescription: 'Précision stable (Mid Ram)',
    bullets: ['qwen2.5-coder:14b', 'Contexte 16k', '1 fichier en parallèle'],
  },
  {
    key: 'elite',
    icon: Rocket,
    fallbackLabel: '🚀 Elite',
    fallbackDescription: 'Haute fidélité',
    bullets: ['qwen2.5-coder:32b', 'Contexte 32k', '2 fichiers en parallèle'],
    badge: 'Recommandé',
  },
  {
    key: 'titan',
    icon: Flame,
    fallbackLabel: '🔥 Titan',
    fallbackDescription: 'Audit expert entreprise',
    bullets: ['qwen2.5-coder:32b', 'Contexte 64k', '4 fichiers en parallèle'],
  },
]

const STEP_LABELS = ['Cible', 'Stratégie', 'Validation']

export default function NewScan() {
  const {
    target,
    setTarget,
    profile,
    setProfile,
    scanMode,
    setScanMode,
    ollamaMode,
    ollamaUrl,
    catalog,
    startScan,
    starting,
    isScanning,
  } = useNexus()

  const [step, setStep] = useState(1)
  const [errors, setErrors] = useState({})

  const preflight = usePreflight({
    target: target.trim(),
    profile,
    mode: scanMode,
    ollamaMode,
    ollamaUrl,
    enabled: step === 3,
  })

  const modes = useMemo(
    () =>
      MODES.map((mode) => ({
        ...mode,
        label: catalog.modes?.[mode.key]?.label || mode.fallbackLabel,
        description: catalog.modes?.[mode.key]?.description || mode.fallbackDescription,
      })),
    [catalog.modes],
  )

  const profiles = useMemo(
    () =>
      PROFILES.map((item) => ({
        ...item,
        label: catalog.profiles?.[item.key]?.label || item.fallbackLabel,
        description: catalog.profiles?.[item.key]?.description || item.fallbackDescription,
      })),
    [catalog.profiles],
  )

  const goToStrategy = () => {
    if (!target.trim()) {
      setErrors({ target: 'Veuillez entrer une cible (URL Git ou chemin local)' })
      return
    }
    setErrors({})
    setStep(2)
  }

  const launch = async () => {
    const result = await startScan()
    if (!result.ok && Object.keys(result.errors).length > 0) {
      setErrors(result.errors)
      if (result.errors.target) setStep(1)
    }
  }

  const repoStats = preflight.data?.repo_stats
  const budget = preflight.data?.profile_effective
  const ollama = preflight.data?.ollama_context

  return (
    <>
      <PageHeader
        eyebrow="Configuration"
        title="Nouvel audit de sécurité"
        description="Définissez la cible, la profondeur d'analyse et le budget matériel. Les deux dimensions restent volontairement indépendantes."
      />

      <div className="mb-6 flex flex-wrap items-center gap-2 text-xs">
        {[1, 2, 3].map((s, i) => (
          <div key={s} className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => (s < step ? setStep(s) : undefined)}
              disabled={s > step}
              className={cn(
                'grid h-7 w-7 place-items-center rounded-full text-[11px] font-semibold ring-1 transition-colors',
                step === s
                  ? 'bg-primary text-primary-foreground ring-primary'
                  : step > s
                    ? 'bg-success text-success-foreground ring-success'
                    : 'bg-muted text-muted-foreground ring-border',
                s < step && 'cursor-pointer',
              )}
            >
              {step > s ? <Check className="h-3.5 w-3.5" /> : s}
            </button>
            <span className={cn('uppercase tracking-wider', step === s ? 'text-foreground' : 'text-muted-foreground')}>
              {STEP_LABELS[i]}
            </span>
            {s < 3 && <span className="mx-2 h-px w-10 bg-border" />}
          </div>
        ))}
      </div>

      {isScanning && (
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-high/30 bg-high/10 p-4 text-sm">
          <div className="flex items-center gap-2 text-high">
            <AlertTriangle className="h-4 w-4" />
            Un audit est déjà en cours. Lancez-en un nouveau une fois celui-ci terminé.
          </div>
          <Button asChild variant="outline" size="sm">
            <Link to="/scan/live">Voir le scan en cours</Link>
          </Button>
        </div>
      )}

      {step === 1 && (
        <SectionCard title="Cible" description="Dépôt Git distant ou chemin local à auditer.">
          <div className="grid gap-5 lg:grid-cols-2">
            <div className="space-y-4">
              <div>
                <Label className="text-xs uppercase tracking-wider text-muted-foreground">
                  Dépôt ou chemin
                </Label>
                <div className="relative mt-2">
                  <FolderGit2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value)
                      setErrors((previous) => ({ ...previous, target: undefined }))
                    }}
                    onKeyDown={(event) => event.key === 'Enter' && goToStrategy()}
                    placeholder="https://github.com/company/repo.git ou /chemin/local"
                    className={cn('pl-9 font-mono text-sm', errors.target && 'border-critical focus-visible:ring-critical')}
                  />
                </div>
                {errors.target && (
                  <p className="mt-1.5 flex items-center gap-1 text-xs text-critical">
                    <AlertTriangle className="h-3 w-3" /> {errors.target}
                  </p>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Les dépôts distants sont clonés dans un répertoire temporaire puis supprimés
                à la fin de l'audit. Les fichiers analysés dépendent du mode choisi à l'étape suivante.
              </p>
            </div>

            <div className="rounded-lg border border-border bg-background/40 p-4">
              <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                <FileCode2 className="h-3.5 w-3.5" /> Périmètre du mode {scanMode}
              </div>
              <ul className="space-y-1.5 text-sm">
                {(modes.find((m) => m.key === scanMode)?.bullets || []).map((bullet) => (
                  <li key={bullet} className="flex items-start gap-2 text-muted-foreground">
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary/70" />
                    <span>{bullet}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-muted-foreground">
                Les statistiques réelles du dépôt (fichiers analysables, volume, exclusions)
                sont calculées par le backend à l'étape de validation.
              </p>
            </div>
          </div>

          <div className="mt-6 flex justify-end">
            <Button onClick={goToStrategy} className="gap-1.5">
              Suivant : stratégie <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        </SectionCard>
      )}

      {step === 2 && (
        <div className="space-y-6">
          <SectionCard
            title="Mode de scan"
            description="Profondeur sémantique de l'analyse : ce que l'IA cherche, pas la vitesse."
          >
            <div className="grid gap-3 md:grid-cols-3">
              {modes.map((mode) => (
                <ChoiceCard
                  key={mode.key}
                  selected={scanMode === mode.key}
                  onClick={() => setScanMode(mode.key)}
                  icon={mode.icon}
                  title={mode.label}
                  tagline={mode.description}
                  bullets={mode.bullets}
                />
              ))}
            </div>
          </SectionCard>

          <SectionCard
            title="Profil de puissance"
            description="Budget matériel et runtime : vitesse, contexte et parallélisme."
          >
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              {profiles.map((item) => (
                <ChoiceCard
                  key={item.key}
                  selected={profile === item.key}
                  onClick={() => setProfile(item.key)}
                  icon={item.icon}
                  title={item.label}
                  tagline={item.description}
                  bullets={item.bullets}
                  badge={item.badge}
                />
              ))}
            </div>
          </SectionCard>

          <div className="flex justify-between">
            <Button variant="outline" onClick={() => setStep(1)} className="gap-1.5">
              <ArrowLeft className="h-4 w-4" /> Retour
            </Button>
            <Button onClick={() => setStep(3)} className="gap-1.5">
              Validation <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="grid gap-5 lg:grid-cols-3">
          <SectionCard
            title="Récapitulatif"
            description="Valeurs effectives calculées par le backend (preflight)."
            className="lg:col-span-2"
            actions={
              <Button variant="ghost" size="sm" onClick={preflight.reload} disabled={preflight.loading}>
                {preflight.loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : 'Recalculer'}
              </Button>
            }
          >
            {preflight.loading && !preflight.data ? (
              <div className="grid gap-3 sm:grid-cols-2">
                {[0, 1, 2, 3, 4, 5].map((i) => (
                  <Skeleton key={i} className="h-16 w-full" />
                ))}
              </div>
            ) : (
              <>
                <dl className="grid gap-3 sm:grid-cols-2">
                  <Fact label="Cible" value={target || '—'} mono />
                  <Fact label="Mode" value={modes.find((m) => m.key === scanMode)?.label || scanMode} />
                  <Fact label="Profil" value={profiles.find((p) => p.key === profile)?.label || profile} />
                  <Fact label="Modèle" value={ollama?.model || '—'} mono />
                  <Fact
                    label="Fenêtre de contexte"
                    value={budget ? `${formatNumber(budget.target_chunk_tokens)} tokens/chunk` : '—'}
                  />
                  <Fact label="Concurrence" value={budget ? `${budget.max_concurrency} worker(s)` : '—'} />
                  <Fact
                    label="Timeouts"
                    value={
                      budget
                        ? `connexion ${formatSeconds(budget.connect_timeout_s)} · lecture ${formatSeconds(budget.read_timeout_s)}`
                        : '—'
                    }
                  />
                  <Fact
                    label="Budget global"
                    value={budget ? formatSeconds(budget.global_scan_timeout_s) : '—'}
                  />
                  <Fact
                    label="Fichiers analysables"
                    value={
                      repoStats
                        ? `${formatNumber(repoStats.analyzable_files)} / ${formatNumber(repoStats.total_files)}`
                        : '—'
                    }
                  />
                  <Fact
                    label="Volume estimé"
                    value={repoStats ? formatBytes(repoStats.total_bytes_est) : '—'}
                  />
                </dl>

                {repoStats?.excluded_reasons?.length > 0 && (
                  <div className="mt-4 rounded-lg border border-border bg-background/40 p-3">
                    <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
                      Exclusions ({formatNumber(repoStats.excluded_files)} fichiers)
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {repoStats.excluded_reasons.slice(0, 8).map((reason) => (
                        <span
                          key={reason.reason}
                          className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground ring-1 ring-border"
                        >
                          {reason.reason} · {reason.count}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {preflight.error && (
                  <div className="mt-5 flex items-start gap-2 rounded-lg border border-high/30 bg-high/10 p-3 text-sm">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-high" />
                    <div>
                      <div className="font-medium text-high">Preflight indisponible</div>
                      <div className="text-xs text-muted-foreground">{preflight.error}</div>
                    </div>
                  </div>
                )}

                {preflight.data?.warnings?.length > 0 && (
                  <div className="mt-5 rounded-lg border border-high/30 bg-high/10 p-3 text-sm">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-high" />
                      <div>
                        <div className="font-medium text-high">Avertissements du preflight</div>
                        <ul className="mt-1 space-y-0.5 text-xs text-muted-foreground">
                          {preflight.data.warnings.map((warning) => (
                            <li key={warning}>• {warning}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </SectionCard>

          <div className="space-y-5">
            <SectionCard title="Runtime Ollama">
              <OllamaConnection error={errors.ollamaUrl} onErrorClear={() => setErrors({})} />
              <div className="mt-4 space-y-2 border-t border-border pt-4 text-sm">
                <Row label="Endpoint résolu" value={<code className="text-xs">{ollama?.base_url || '—'}</code>} />
                <Row
                  label="Joignable"
                  value={
                    ollama?.reachable ? (
                      <span className="inline-flex items-center gap-1.5 text-success">
                        <Check className="h-3.5 w-3.5" /> Oui
                      </span>
                    ) : (
                      <span className="text-high">Non</span>
                    )
                  }
                />
                <Row label="Modèles installés" value={<span className="text-xs">{ollama?.tags?.length ?? 0}</span>} />
              </div>

              <Button
                onClick={launch}
                disabled={starting || isScanning}
                className="mt-5 h-11 w-full gap-2 text-base"
              >
                {starting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                {starting ? 'Lancement…' : "Lancer l'audit"}
              </Button>
              <Button asChild variant="ghost" className="mt-2 w-full">
                <Link to="/" className="text-xs">
                  Annuler
                </Link>
              </Button>
              <div className="mt-4 flex items-center gap-1.5 text-[11px] text-muted-foreground">
                <Cpu className="h-3 w-3" /> L'analyse s'exécute sur votre runtime Ollama.
              </div>
            </SectionCard>

            <Button variant="outline" onClick={() => setStep(2)} className="w-full gap-1.5">
              <ArrowLeft className="h-4 w-4" /> Modifier la stratégie
            </Button>
          </div>
        </div>
      )}
    </>
  )
}

function Fact({ label, value, mono }) {
  return (
    <div className="rounded-lg border border-border bg-background/40 px-3 py-2.5">
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn('mt-0.5 break-all text-sm', mono && 'font-mono text-xs')}>{value}</div>
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate text-right">{value}</span>
    </div>
  )
}
