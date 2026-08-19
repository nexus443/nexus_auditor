import { ChevronRight } from 'lucide-react'

import { SeverityBadge } from './SeverityBadge'
import { confidenceLabel, confidenceTone } from '@/utils/mappers'
import { cn } from '@/lib/utils'

/**
 * Tableau des vulnérabilités réelles renvoyées par `/scan/status`.
 * La colonne « CWE » de la maquette est remplacée par le `type` normalisé par
 * le moteur Nexus (SQL_INJECTION, HARDCODED_SECRET, …), seule taxonomie
 * réellement produite par le backend.
 */
export function FindingsTable({ findings, selectedId, onSelect }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-card/40">
      <table className="w-full min-w-[640px] text-sm">
        <thead className="bg-muted/50 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-4 py-3">Sévérité</th>
            <th className="px-4 py-3">Vulnérabilité</th>
            <th className="hidden md:table-cell px-4 py-3">Fichier</th>
            <th className="hidden lg:table-cell px-4 py-3">Type</th>
            <th className="hidden lg:table-cell px-4 py-3">Confiance</th>
            <th className="px-4 py-3" />
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.id}
              onClick={() => onSelect(f)}
              className={cn(
                'cursor-pointer border-t border-border/60 transition-colors hover:bg-accent/40',
                selectedId === f.id && 'bg-accent/40',
              )}
            >
              <td className="px-4 py-3">
                <SeverityBadge severity={f.severity} label={f.severityLabel} />
              </td>
              <td className="px-4 py-3">
                <div className="font-medium">{f.title}</div>
                <div className="text-xs text-muted-foreground">
                  {f.category} · #{f.id}
                  {f.needsManualReview && ' · revue manuelle'}
                </div>
              </td>
              <td className="hidden md:table-cell px-4 py-3 font-mono text-xs text-muted-foreground">
                {f.file || '—'}
                {f.line ? `:${f.line}` : ''}
              </td>
              <td className="hidden lg:table-cell px-4 py-3 text-xs">{f.category}</td>
              <td className={cn('hidden lg:table-cell px-4 py-3 text-xs', confidenceTone(f.confidence))}>
                {f.confidence !== null ? `${confidenceLabel(f.confidence)} · ${f.confidence}%` : '—'}
              </td>
              <td className="px-4 py-3 text-right text-muted-foreground">
                <ChevronRight className="ml-auto h-4 w-4" />
              </td>
            </tr>
          ))}
          {findings.length === 0 && (
            <tr>
              <td colSpan={6} className="px-4 py-12 text-center text-sm text-muted-foreground">
                Aucune vulnérabilité ne correspond à ces filtres.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
