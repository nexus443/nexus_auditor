import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileJson,
  Filter,
  Search,
  ShieldCheck,
  Terminal,
} from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { FindingsTable } from '@/components/nexus/FindingsTable'
import { FindingDetailDrawer } from '@/components/nexus/FindingDetailDrawer'
import { ExecutiveView } from '@/components/nexus/ExecutiveView'
import { EmptyState } from '@/components/nexus/EmptyState'
import { LogStream } from '@/components/nexus/LogStream'
import { StatusPill } from '@/components/nexus/StatusPill'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { SectionCard } from '@/components/nexus/SectionCard'
import { useNexus } from '@/hooks/useNexus.jsx'
import { useToasts } from '@/components/Toast.jsx'
import { INTERRUPTED_STATES, SEVERITIES } from '@/utils/mappers'
import { shortTargetName } from '@/utils/format'
import { cn } from '@/lib/utils'

const SEVERITY_FILTERS = ['all', ...SEVERITIES]
const SEVERITY_LABELS = {
  all: 'Toutes',
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Autres',
}

export default function Results() {
  const {
    status,
    findings,
    severityCounts,
    scanState,
    scanMode,
    generateFix,
    fixLoadingId,
    downloadReport,
    downloadJson,
  } = useNexus()
  const toast = useToasts()

  const [searchParams, setSearchParams] = useSearchParams()
  const [severity, setSeverity] = useState('all')
  const [selectedId, setSelectedId] = useState(null)
  const [logsOpen, setLogsOpen] = useState(false)
  const [logLevelFilter, setLogLevelFilter] = useState('all')

  // La recherche est portée par l'URL (`?q=`) : la barre de recherche globale
  // de l'en-tête et le champ de cette page pilotent donc le même filtre.
  const search = searchParams.get('q') || ''

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return findings.filter((f) => {
      if (severity !== 'all' && f.severity !== severity) return false
      if (!query) return true
      return (
        f.title?.toLowerCase().includes(query) ||
        f.description?.toLowerCase().includes(query) ||
        f.file?.toLowerCase().includes(query) ||
        f.snippet?.toLowerCase().includes(query) ||
        f.category?.toLowerCase().includes(query) ||
        (f.line !== null && String(f.line).includes(query))
      )
    })
  }, [findings, severity, search])

  const selected = useMemo(
    () => findings.find((f) => f.id === selectedId) || null,
    [findings, selectedId],
  )

  const onSearchChange = (value) => {
    const next = new URLSearchParams(searchParams)
    if (value.trim()) next.set('q', value.trim())
    else next.delete('q')
    setSearchParams(next, { replace: true })
  }

  const copyJson = (finding) => {
    navigator.clipboard?.writeText(JSON.stringify(finding.raw, null, 2))
    toast.success('JSON copié dans le presse-papier')
  }

  const copyLogLine = (log) => {
    navigator.clipboard?.writeText(`[${log.time}] ${log.msg}`)
    toast.success('Log copié')
  }

  const hasScan = status.progress > 0 || findings.length > 0
  const isCompleted = scanState === 'completed'
  const isInterrupted = INTERRUPTED_STATES.includes(scanState)
  const interruptionLabel =
    scanState === 'timeout'
      ? 'timeout global atteint'
      : scanState === 'cancelled'
        ? 'arrêt utilisateur'
        : 'erreur du moteur'

  return (
    <>
      <PageHeader
        eyebrow={isInterrupted ? 'Détections partielles' : "Résultats d'audit"}
        title={
          status.target_dir
            ? `${shortTargetName(status.target_dir)} · ${status.mode || 'scan'}`
            : "Résultats d'audit"
        }
        description={
          hasScan
            ? `${findings.length} vulnérabilité(s) retenue(s) sur ${status.stats?.files || 0} fichier(s) analysé(s)${
                status.profile ? ` · profil ${status.profile}` : ''
              }${isInterrupted ? ' · audit interrompu, résultats partiels' : ''}.`
            : 'Aucun résultat disponible pour le moment.'
        }
        actions={
          <>
            <StatusPill status={scanState} />
            <Button variant="outline" className="gap-1.5" onClick={() => setLogsOpen(true)}>
              <Terminal className="h-4 w-4" /> Logs
            </Button>
            {/* Le rapport final n'existe que pour un audit complété : pas de
                bouton d'export de rapport pour un scan interrompu. */}
            {isCompleted && (
              <Button variant="outline" className="gap-1.5" onClick={() => downloadReport(status.id)}>
                <Download className="h-4 w-4" /> Rapport HTML
              </Button>
            )}
            {(isCompleted || findings.length > 0) && (
              <Button variant="outline" className="gap-1.5" onClick={() => downloadJson(status.id)}>
                <FileJson className="h-4 w-4" /> JSON{isInterrupted ? ' (partiel)' : ''}
              </Button>
            )}
            <Button asChild className="gap-1.5">
              <Link to="/scan/new">
                <ShieldCheck className="h-4 w-4" /> Nouvel audit
              </Link>
            </Button>
          </>
        }
      />

      {isInterrupted && hasScan && (
        <SectionCard className="mb-5 border-medium/40 bg-medium/5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-medium" />
            <div className="min-w-0 text-sm">
              <span className="font-semibold">Audit interrompu ({interruptionLabel}).</span>{' '}
              <span className="text-muted-foreground">
                Les détections listées sont partielles : la corrélation n'a pas abouti (confiance non
                calculée) et le rapport final n'a pas été généré. Progression atteinte :{' '}
                {Math.round(Number(status.progress) || 0)}%.
              </span>
            </div>
          </div>
        </SectionCard>
      )}

      {findings.length === 0 ? (
        <EmptyState
          icon={CheckCircle2}
          tone={hasScan ? 'success' : 'default'}
          title={
            hasScan
              ? "Aucune vulnérabilité retenue selon le niveau d'analyse sélectionné"
              : 'Aucun audit exécuté'
          }
          description={
            hasScan
              ? scanMode === 'rapid' || scanMode === 'deep'
                ? 'Essayez le mode DevSecOps pour une analyse exhaustive (toutes sévérités, tous types de fichiers).'
                : "Le moteur n'a retenu aucune vulnérabilité au-dessus des seuils de confiance du mode sélectionné."
              : 'Lancez un audit pour voir apparaître ici les vulnérabilités détectées.'
          }
          action={
            <>
              <Button asChild>
                <Link to="/scan/new">{hasScan ? 'Relancer un audit' : 'Configurer un audit'}</Link>
              </Button>
              {hasScan && (
                <Button variant="outline" onClick={() => setLogsOpen(true)}>
                  Consulter les logs
                </Button>
              )}
            </>
          }
        />
      ) : (
        <Tabs defaultValue="exec" className="w-full">
          <TabsList className="border border-border bg-card/60">
            <TabsTrigger value="exec">Vue exécutive</TabsTrigger>
            <TabsTrigger value="tech">Vue technique</TabsTrigger>
          </TabsList>

          <TabsContent value="exec" className="mt-5">
            <ExecutiveView
              findings={findings}
              counts={severityCounts}
              confidence={status.confidence_score ?? null}
              target={status.target_dir ? shortTargetName(status.target_dir) : null}
              onSelect={(finding) => setSelectedId(finding.id)}
            />
          </TabsContent>

          <TabsContent value="tech" className="mt-5 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="inline-flex flex-wrap items-center gap-1 rounded-md border border-border bg-card/60 p-0.5 text-[11px]">
                <Filter className="ml-1.5 h-3 w-3 text-muted-foreground" />
                {SEVERITY_FILTERS.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setSeverity(s)}
                    className={cn(
                      'rounded px-2 py-1 transition-colors',
                      severity === s
                        ? 'bg-muted text-foreground'
                        : 'text-muted-foreground hover:text-foreground',
                    )}
                  >
                    {SEVERITY_LABELS[s]}
                    {s !== 'all' && severityCounts[s] ? ` (${severityCounts[s]})` : ''}
                  </button>
                ))}
              </div>

              <div className="relative min-w-[220px] flex-1 sm:max-w-xs">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={search}
                  onChange={(event) => onSearchChange(event.target.value)}
                  placeholder="Rechercher…"
                  className="h-8 pl-9 text-xs"
                />
              </div>

              <span className="text-xs text-muted-foreground">
                {filtered.length} vulnérabilité(s)
              </span>
            </div>

            <FindingsTable
              findings={filtered}
              selectedId={selectedId}
              onSelect={(finding) => setSelectedId(finding.id)}
            />
          </TabsContent>
        </Tabs>
      )}

      <FindingDetailDrawer
        finding={selected}
        onOpenChange={(open) => !open && setSelectedId(null)}
        onGenerateFix={(finding) => generateFix(finding.id)}
        onCopyJson={copyJson}
        fixLoading={fixLoadingId === selectedId}
      />

      <Dialog open={logsOpen} onOpenChange={setLogsOpen}>
        <DialogContent className="flex h-[80vh] max-w-4xl flex-col bg-card">
          <DialogHeader>
            <DialogTitle>Logs d'exécution</DialogTitle>
            <p className="font-mono text-xs text-muted-foreground">
              {(status.logs || []).length} entrée(s) · {status.estimated_time || '—'}
            </p>
          </DialogHeader>
          <LogStream
            logs={status.logs}
            level={logLevelFilter}
            onLevelChange={setLogLevelFilter}
            onCopyLine={copyLogLine}
            className="min-h-0 flex-1"
          />
        </DialogContent>
      </Dialog>
    </>
  )
}
