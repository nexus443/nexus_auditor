import { Link } from 'react-router-dom'
import { Activity, AlertTriangle, ArrowRight, Cpu, Plus, ShieldAlert, ShieldCheck } from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { SectionCard } from '@/components/nexus/SectionCard'
import { StatCard } from '@/components/nexus/StatCard'
import { ScoreRing } from '@/components/nexus/ScoreRing'
import { SeverityBar } from '@/components/nexus/SeverityBar'
import { StatusPill } from '@/components/nexus/StatusPill'
import { RuntimeStatus } from '@/components/nexus/RuntimeStatus'
import { ActivityFeed } from '@/components/nexus/ActivityFeed'
import { EmptyState } from '@/components/nexus/EmptyState'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useNexus } from '@/hooks/useNexus.jsx'
import { totalFindings } from '@/utils/mappers'
import { formatDateTime, formatDuration, shortTargetName } from '@/utils/format'

export default function Dashboard() {
  const {
    status,
    statusLoading,
    severityCounts,
    scanState,
    isScanning,
    history,
    historyLoading,
    runtime,
    health,
  } = useNexus()

  const total = totalFindings(severityCounts)
  const confidence = Number(status.confidence_score) || 0
  const hasScanned = total > 0 || status.progress > 0 || history.length > 0

  const riskLabel =
    severityCounts.critical > 0
      ? 'Risque critique — correction immédiate requise'
      : severityCounts.high > 0
        ? 'Risque élevé — à traiter dans le sprint'
        : total > 0
          ? 'Risque modéré — améliorations recommandées'
          : 'Aucune vulnérabilité retenue sur le dernier audit'

  return (
    <>
      <PageHeader
        eyebrow="Vue d'ensemble"
        title="Posture de sécurité"
        description="Synthèse du dernier audit Nexus : vulnérabilités retenues, runtime d'inférence et activité du moteur."
        actions={
          <Button asChild className="gap-1.5">
            <Link to="/scan/new">
              <Plus className="h-4 w-4" /> Démarrer un audit
            </Link>
          </Button>
        }
      />

      {statusLoading && !hasScanned ? (
        <div className="grid gap-5 xl:grid-cols-3">
          <Skeleton className="h-56 xl:col-span-2" />
          <Skeleton className="h-56" />
        </div>
      ) : !hasScanned ? (
        <EmptyState
          icon={ShieldCheck}
          title="Aucun audit enregistré"
          description="Lancez votre premier audit pour voir apparaître ici la posture de sécurité, les vulnérabilités détectées et l'activité du moteur d'analyse."
          action={
            <Button asChild className="gap-1.5">
              <Link to="/scan/new">
                <Plus className="h-4 w-4" /> Configurer un audit
              </Link>
            </Button>
          }
        />
      ) : (
        <>
          <div className="grid gap-5 xl:grid-cols-3">
            <SectionCard className="xl:col-span-2">
              <div className="flex flex-col items-center gap-6 md:flex-row md:items-center md:gap-8">
                <ScoreRing score={confidence} label="Confiance" suffix="%" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs uppercase tracking-wider text-muted-foreground">
                      Dernier audit
                    </span>
                    <StatusPill status={scanState} />
                  </div>
                  <div className="mt-1 text-lg font-semibold">{riskLabel}</div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {status.target_dir ? (
                      <>
                        Cible <span className="font-mono">{shortTargetName(status.target_dir)}</span>
                        {status.mode ? ` · mode ${status.mode}` : ''}
                        {status.profile ? ` · profil ${status.profile}` : ''} ·{' '}
                        {status.stats?.files || 0} fichier(s) analysé(s).
                      </>
                    ) : (
                      'Aucune cible enregistrée pour le scan courant.'
                    )}{' '}
                    Score de confiance moyen des détections : {confidence}%.
                  </p>
                  <div className="mt-4">
                    <SeverityBar counts={severityCounts} />
                  </div>
                </div>
              </div>
            </SectionCard>
            <RuntimeStatus
              preflight={runtime.data}
              loading={runtime.loading}
              error={runtime.error}
              apiHealth={health.api}
            />
          </div>

          <div className="mt-5 grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              label="Vulnérabilités"
              value={total}
              icon={ShieldAlert}
              tone="primary"
              delta={`${status.stats?.files || 0} fichier(s) analysé(s)`}
            />
            <StatCard
              label="Critical"
              value={severityCounts.critical}
              icon={AlertTriangle}
              tone="critical"
              delta={severityCounts.critical > 0 ? 'Action immédiate' : 'Aucune'}
            />
            <StatCard
              label="High"
              value={severityCounts.high}
              icon={AlertTriangle}
              tone="warning"
              delta={severityCounts.high > 0 ? 'À planifier' : 'Aucune'}
            />
            <StatCard
              label="Modèle actif"
              value={
                <span className="font-mono text-base">
                  {runtime.data?.ollama_context?.model || '—'}
                </span>
              }
              icon={Cpu}
              delta={
                runtime.data?.profile_effective
                  ? `Profil ${runtime.data.profile_effective.profile_name} · ${runtime.data.profile_effective.max_concurrency} worker(s)`
                  : 'Runtime non résolu'
              }
            />
          </div>

          <div className="mt-5 grid gap-5 xl:grid-cols-3">
            <SectionCard
              title="Audits récents"
              actions={
                <Link
                  to="/history"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  Tout voir <ArrowRight className="h-3 w-3" />
                </Link>
              }
              className="xl:col-span-2"
            >
              {historyLoading ? (
                <div className="space-y-3">
                  {[0, 1, 2].map((i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : history.length === 0 ? (
                <p className="py-6 text-center text-sm text-muted-foreground">
                  Aucun audit dans l'historique.
                </p>
              ) : (
                <ul className="divide-y divide-border/60">
                  {history.slice(0, 4).map((scan) => (
                    <li key={scan.id} className="flex min-w-0 items-center gap-4 py-3 first:pt-0 last:pb-0">
                      <div className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-muted ring-1 ring-border">
                        <Activity className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium">{scan.target}</div>
                        <div className="truncate font-mono text-xs text-muted-foreground">
                          {scan.id}
                          {scan.mode ? ` · ${scan.mode}` : ''}
                          {scan.profile ? ` · ${scan.profile}` : ''}
                          {scan.durationSeconds !== null
                            ? ` · ${formatDuration(scan.durationSeconds)}`
                            : ''}
                        </div>
                      </div>
                      <div className="hidden items-center gap-2 text-xs sm:flex">
                        {scan.counts.critical > 0 && (
                          <span className="rounded bg-critical/15 px-1.5 py-0.5 text-critical ring-1 ring-critical/30">
                            {scan.counts.critical} crit
                          </span>
                        )}
                        {scan.counts.high > 0 && (
                          <span className="rounded bg-high/15 px-1.5 py-0.5 text-high ring-1 ring-high/30">
                            {scan.counts.high} high
                          </span>
                        )}
                      </div>
                      <span className="hidden text-[11px] text-muted-foreground lg:block">
                        {formatDateTime(scan.date)}
                      </span>
                      <StatusPill status={scan.status} />
                    </li>
                  ))}
                </ul>
              )}
            </SectionCard>
            <ActivityFeed logs={status.logs} />
          </div>

          {isScanning && (
            <div className="mt-5">
              <SectionCard>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2 text-sm">
                    <Activity className="h-4 w-4 animate-pulse text-primary" />
                    Un audit est en cours ({Math.round(status.progress)}%).
                  </div>
                  <Button asChild variant="outline" size="sm">
                    <Link to="/scan/live">Suivre en direct</Link>
                  </Button>
                </div>
              </SectionCard>
            </div>
          )}
        </>
      )}
    </>
  )
}
