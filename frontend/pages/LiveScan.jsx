import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, FileCode2, ListChecks, Radio, Sparkles, Square } from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { SectionCard } from '@/components/nexus/SectionCard'
import { StageTimeline } from '@/components/nexus/StageTimeline'
import { SeverityBadge } from '@/components/nexus/SeverityBadge'
import { StatusPill } from '@/components/nexus/StatusPill'
import { LogStream } from '@/components/nexus/LogStream'
import { EmptyState } from '@/components/nexus/EmptyState'
import { Button } from '@/components/ui/button'
import { useNexus } from '@/hooks/useNexus.jsx'
import { useToasts } from '@/components/Toast.jsx'
import { formatNumber, shortTargetName } from '@/utils/format'

export default function LiveScan() {
  const { status, stageReport, findings, isScanning, scanState, stopScan, runtime } = useNexus()
  const toast = useToasts()
  const [logLevelFilter, setLogLevelFilter] = useState('all')

  const telemetry = status.telemetry || {}
  const progress = Math.max(0, Math.min(100, Number(status.progress) || 0))
  const started = isScanning || progress > 0

  const copyLine = (log) => {
    navigator.clipboard?.writeText(`[${log.time}] ${log.msg}`)
    toast.success('Log copié')
  }

  const downloadLogs = () => {
    const text = (status.logs || []).map((log) => `[${log.time}] ${log.msg}`).join('\n')
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `nexus-scan-logs-${Date.now()}.txt`
    anchor.click()
    URL.revokeObjectURL(url)
    toast.success('Logs téléchargés')
  }

  if (!started) {
    return (
      <>
        <PageHeader eyebrow="En direct" title="Scan en direct" />
        <EmptyState
          icon={Radio}
          title="Aucun audit en cours"
          description="Configurez une cible et lancez un audit pour suivre en direct la progression du pipeline, les événements du moteur et les vulnérabilités détectées."
          action={
            <>
              <Button asChild>
                <Link to="/scan/new">Configurer un audit</Link>
              </Button>
              {findings.length > 0 && (
                <Button asChild variant="outline">
                  <Link to="/results">Voir les derniers résultats</Link>
                </Button>
              )}
            </>
          }
        />
      </>
    )
  }

  return (
    <>
      <PageHeader
        eyebrow={isScanning ? 'En cours' : 'Terminé'}
        title={`Scan · ${shortTargetName(status.target_dir)}`}
        description="Les vulnérabilités apparaissent au fil de l'analyse. L'exécution reste locale à votre infrastructure."
        actions={
          <>
            <StatusPill status={scanState} />
            {isScanning ? (
              <Button variant="outline" className="gap-1.5" onClick={stopScan}>
                <Square className="h-4 w-4" /> Arrêter le scan
              </Button>
            ) : (
              <Button asChild className="gap-1.5">
                <Link to="/results">
                  <ListChecks className="h-4 w-4" /> Voir les résultats
                </Link>
              </Button>
            )}
          </>
        }
      />

      <StageTimeline
        stages={stageReport.stages}
        currentIndex={stageReport.currentIndex}
        terminal={stageReport.terminal}
      />

      <div className="mt-5 grid gap-5 xl:grid-cols-3">
        <SectionCard className="xl:col-span-2">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Progression globale
              </div>
              <div className="mt-1 text-2xl font-semibold tracking-tight">{Math.round(progress)}%</div>
            </div>
            <div className="text-right text-xs text-muted-foreground">
              <div>
                Temps estimé <span className="font-mono">{status.estimated_time || '—'}</span>
              </div>
              <div>
                Fichiers{' '}
                <span className="font-mono">
                  {formatNumber(telemetry.files_processed ?? status.stats?.files ?? 0)}
                  {telemetry.files_scheduled ? ` / ${formatNumber(telemetry.files_scheduled)}` : ''}
                </span>
              </div>
            </div>
          </div>
          <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-muted">
            <div
              className="h-full bg-gradient-to-r from-primary via-primary to-primary/60 transition-[width] duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-5 flex items-start gap-3 rounded-lg border border-border bg-background/40 p-3">
            <FileCode2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
            <div className="min-w-0">
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
                Fichier en cours d'analyse
              </div>
              <div className="truncate font-mono text-sm">
                {status.current_file || (isScanning ? 'Préparation…' : '—')}
              </div>
            </div>
          </div>
        </SectionCard>

        <SectionCard title="Moteur d'analyse">
          <div className="flex items-start gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-primary/10 ring-1 ring-primary/30">
              <Sparkles className={`h-5 w-5 text-primary ${isScanning ? 'animate-pulse' : ''}`} />
            </div>
            <div className="min-w-0">
              <div className="truncate text-sm font-medium">
                {runtime.data?.ollama_context?.model || status.profile || '—'}
              </div>
              <div className="text-xs text-muted-foreground">
                {status.mode ? `Mode ${status.mode}` : 'Mode inconnu'}
                {status.profile ? ` · profil ${status.profile}` : ''}
              </div>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2 text-center">
            <Mini label="Requêtes IA" value={formatNumber(telemetry.llm_requests ?? 0)} />
            <Mini
              label="Chunks"
              value={`${formatNumber(telemetry.chunks_processed ?? 0)}/${formatNumber(telemetry.chunks_total ?? 0)}`}
            />
            <Mini label="Tokens" value={compactNumber(telemetry.tokens_estimated_total)} />
          </div>
          <div className="mt-4 grid grid-cols-4 gap-2 text-center">
            <Stat label="Crit" value={status.stats?.critical ?? 0} tone="text-critical" />
            <Stat label="High" value={status.stats?.high ?? 0} tone="text-high" />
            <Stat label="Med" value={status.stats?.medium ?? 0} tone="text-medium" />
            <Stat label="Low" value={status.stats?.low ?? 0} tone="text-low" />
          </div>
        </SectionCard>
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <SectionCard
          title="Vulnérabilités détectées"
          description="Remontées en temps réel par le moteur"
          actions={
            <span className="inline-flex items-center gap-1.5 text-xs text-primary">
              <Activity className="h-3.5 w-3.5" /> {findings.length} au total
            </span>
          }
        >
          {findings.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {isScanning
                ? 'Aucune vulnérabilité retenue pour le moment.'
                : "Aucune vulnérabilité retenue selon le niveau d'analyse sélectionné."}
            </p>
          ) : (
            <ul className="max-h-80 divide-y divide-border/60 overflow-y-auto custom-scrollbar">
              {[...findings].reverse().map((f) => (
                <li key={f.id} className="flex items-start gap-3 py-3 first:pt-0">
                  <SeverityBadge severity={f.severity} label={f.severityLabel} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{f.title}</div>
                    <div className="truncate font-mono text-xs text-muted-foreground">
                      {f.file || '—'}
                      {f.line ? `:${f.line}` : ''}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard title="Journal d'exécution" description="Événements structurés du moteur">
          <LogStream
            logs={status.logs}
            level={logLevelFilter}
            onLevelChange={setLogLevelFilter}
            onCopyLine={copyLine}
            onDownload={downloadLogs}
            autoScroll={isScanning}
            className="max-h-80"
          />
        </SectionCard>
      </div>
    </>
  )
}

function compactNumber(value) {
  const number = Number(value)
  if (!Number.isFinite(number) || number <= 0) return '0'
  if (number >= 1_000_000) return `${(number / 1_000_000).toFixed(1)}M`
  if (number >= 1000) return `${Math.round(number / 1000)}k`
  return String(number)
}

function Mini({ label, value }) {
  return (
    <div className="rounded-md border border-border bg-background/40 p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-mono text-sm">{value}</div>
    </div>
  )
}

function Stat({ label, value, tone }) {
  return (
    <div className="rounded-md border border-border bg-background/40 p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`mt-0.5 font-mono text-sm font-semibold ${tone}`}>{value}</div>
    </div>
  )
}
