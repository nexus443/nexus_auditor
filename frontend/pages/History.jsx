import { Link } from 'react-router-dom'
import { Download, FileJson, History as HistoryIcon, RefreshCw } from 'lucide-react'

import { PageHeader } from '@/components/nexus/PageHeader'
import { StatusPill } from '@/components/nexus/StatusPill'
import { EmptyState } from '@/components/nexus/EmptyState'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useNexus } from '@/hooks/useNexus.jsx'
import { formatDateTime, formatDuration } from '@/utils/format'

/**
 * Historique persistant des audits (`GET /history`).
 *
 * L'ancienne interface chargeait déjà cet endpoint mais ne l'affichait nulle
 * part : la donnée est désormais exploitée.
 */
export default function History() {
  const { history, historyLoading, historyError, refreshHistory, downloadReport, downloadJson } =
    useNexus()

  return (
    <>
      <PageHeader
        eyebrow="Traçabilité"
        title="Historique des audits"
        description="Les 50 derniers audits conservés par le backend, avec leur configuration complète."
        actions={
          <Button variant="outline" className="gap-1.5" onClick={refreshHistory} disabled={historyLoading}>
            <RefreshCw className={`h-4 w-4 ${historyLoading ? 'animate-spin' : ''}`} /> Rafraîchir
          </Button>
        }
      />

      {historyLoading && history.length === 0 ? (
        <div className="space-y-2">
          {[0, 1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : historyError ? (
        <EmptyState
          icon={HistoryIcon}
          tone="critical"
          title="Historique indisponible"
          description={historyError}
          action={<Button onClick={refreshHistory}>Réessayer</Button>}
        />
      ) : history.length === 0 ? (
        <EmptyState
          icon={HistoryIcon}
          title="Aucun audit enregistré"
          description="Les audits terminés apparaîtront ici avec leur cible, leur configuration et leurs résultats."
          action={
            <Button asChild>
              <Link to="/scan/new">Lancer un audit</Link>
            </Button>
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border bg-card/40">
          <table className="w-full min-w-[880px] text-sm">
            <thead className="bg-muted/50 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-4 py-3">Audit</th>
                <th className="px-4 py-3">Cible</th>
                <th className="hidden md:table-cell px-4 py-3">Mode</th>
                <th className="hidden md:table-cell px-4 py-3">Profil</th>
                <th className="hidden lg:table-cell px-4 py-3">Durée</th>
                <th className="hidden lg:table-cell px-4 py-3">Confiance</th>
                <th className="px-4 py-3">Résultats</th>
                <th className="px-4 py-3">Statut</th>
                <th className="px-4 py-3">Exports</th>
              </tr>
            </thead>
            <tbody>
              {history.map((scan) => (
                <tr key={`${scan.id}-${scan.date}`} className="border-t border-border/60 transition-colors hover:bg-accent/40">
                  <td className="px-4 py-3">
                    <div className="font-mono text-xs">{scan.id}</div>
                    <div className="text-[11px] text-muted-foreground">{formatDateTime(scan.date)}</div>
                  </td>
                  <td className="max-w-[240px] truncate px-4 py-3" title={scan.target}>
                    {scan.target}
                  </td>
                  <td className="hidden md:table-cell px-4 py-3 capitalize">{scan.mode || '—'}</td>
                  <td className="hidden md:table-cell px-4 py-3 capitalize">{scan.profile || '—'}</td>
                  <td className="hidden lg:table-cell px-4 py-3 font-mono text-xs">
                    {scan.durationSeconds !== null ? formatDuration(scan.durationSeconds) : '—'}
                  </td>
                  <td className="hidden lg:table-cell px-4 py-3 font-mono text-xs">
                    {scan.confidence !== null ? `${scan.confidence}%` : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 text-[11px]">
                      {scan.counts.critical > 0 && (
                        <span className="rounded bg-critical/15 px-1.5 py-0.5 text-critical ring-1 ring-critical/30">
                          {scan.counts.critical}C
                        </span>
                      )}
                      {scan.counts.high > 0 && (
                        <span className="rounded bg-high/15 px-1.5 py-0.5 text-high ring-1 ring-high/30">
                          {scan.counts.high}H
                        </span>
                      )}
                      {scan.counts.medium > 0 && (
                        <span className="rounded bg-medium/15 px-1.5 py-0.5 text-medium ring-1 ring-medium/30">
                          {scan.counts.medium}M
                        </span>
                      )}
                      {scan.counts.low > 0 && (
                        <span className="rounded bg-low/15 px-1.5 py-0.5 text-low ring-1 ring-low/30">
                          {scan.counts.low}L
                        </span>
                      )}
                      {scan.total === 0 && <span className="text-muted-foreground">Aucune</span>}
                    </div>
                    <div className="mt-1 text-[11px] text-muted-foreground">
                      {scan.files} fichier(s)
                      {scan.skipped ? ` · ${scan.skipped} ignoré(s)` : ''}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={scan.status} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Rapport HTML"
                        onClick={() => downloadReport(scan.id)}
                      >
                        <Download className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        title="Export JSON"
                        onClick={() => downloadJson(scan.id)}
                      >
                        <FileJson className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
