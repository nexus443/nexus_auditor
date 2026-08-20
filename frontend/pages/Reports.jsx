import { Link } from 'react-router-dom'
import { Download, FileJson, FileText } from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { SectionCard } from '@/components/nexus/SectionCard'
import { StatusPill } from '@/components/nexus/StatusPill'
import { EmptyState } from '@/components/nexus/EmptyState'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useNexus } from '@/hooks/useNexus.jsx'
import { formatDateTime, formatDuration } from '@/utils/format'

/**
 * Bibliothèque de rapports.
 *
 * Nexus expose deux formats d'export réels : le rapport HTML
 * (`GET /export/report`) et l'export JSON (`GET /export/json`), tous deux
 * paramétrables par `scan_id`. La maquette proposait également un export PDF,
 * qui n'existe pas côté backend : il n'a pas été reproduit.
 */
export default function Reports() {
  const { history, historyLoading, status, scanState, findings, downloadReport, downloadJson } =
    useNexus()

  const currentScanId = status.id
  // Le rapport final n'existe que si l'audit est réellement complété :
  // `!is_scanning` ne signifie pas « terminé » (timeout/échec/annulation).
  const currentCompleted = scanState === 'completed'

  return (
    <>
      <PageHeader
        eyebrow="Bibliothèque"
        title="Rapports"
        description="Exports générés à la demande depuis les audits conservés par le backend."
      />

      {currentScanId && (
        <SectionCard
          title="Audit courant"
          description="Dernier audit chargé dans l'interface"
          className="mb-5"
          actions={<StatusPill status={scanState} />}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="truncate text-sm font-medium">{status.target_dir || '—'}</div>
              <div className="truncate font-mono text-xs text-muted-foreground">
                {currentScanId}
                {status.mode ? ` · ${status.mode}` : ''}
                {status.profile ? ` · ${status.profile}` : ''}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              {currentCompleted ? (
                <>
                  <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadReport(currentScanId)}>
                    <Download className="h-3.5 w-3.5" /> HTML
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadJson(currentScanId)}>
                    <FileJson className="h-3.5 w-3.5" /> JSON
                  </Button>
                </>
              ) : findings.length > 0 && !status.is_scanning ? (
                <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadJson(currentScanId)}>
                  <FileJson className="h-3.5 w-3.5" /> JSON (partiel)
                </Button>
              ) : (
                <span className="text-xs text-muted-foreground">
                  {status.is_scanning ? 'Audit en cours…' : 'Rapport final indisponible (audit non complété)'}
                </span>
              )}
            </div>
          </div>
        </SectionCard>
      )}

      {historyLoading && history.length === 0 ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <Skeleton key={i} className="h-44 w-full" />
          ))}
        </div>
      ) : history.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="Aucun rapport disponible"
          description="Chaque audit terminé peut être exporté en rapport HTML ou en JSON brut."
          action={
            <Button asChild>
              <Link to="/scan/new">Lancer un audit</Link>
            </Button>
          }
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {history.map((scan) => (
            <SectionCard key={`${scan.id}-${scan.date}`}>
              <div className="flex items-start justify-between gap-2">
                <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-primary/10 ring-1 ring-primary/30">
                  <FileText className="h-5 w-5 text-primary" />
                </div>
                <StatusPill status={scan.status} />
              </div>
              <div className="mt-3 truncate text-sm font-semibold" title={scan.target}>
                {scan.target}
              </div>
              <div className="text-xs text-muted-foreground">
                {formatDateTime(scan.date)}
                {scan.mode ? ` · ${scan.mode}` : ''}
                {scan.durationSeconds !== null ? ` · ${formatDuration(scan.durationSeconds)}` : ''}
              </div>
              <div className="mt-1 text-xs text-muted-foreground">
                {scan.counts.critical + scan.counts.high} problème(s) prioritaire(s) ·{' '}
                {scan.total} au total
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadReport(scan.id)}>
                  <Download className="h-3.5 w-3.5" /> HTML
                </Button>
                <Button size="sm" variant="outline" className="gap-1.5" onClick={() => downloadJson(scan.id)}>
                  <FileJson className="h-3.5 w-3.5" /> JSON
                </Button>
              </div>
            </SectionCard>
          ))}
        </div>
      )}
    </>
  )
}
