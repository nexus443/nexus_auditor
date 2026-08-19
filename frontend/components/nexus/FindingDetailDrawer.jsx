import { AlertTriangle, Copy, Loader2, Sparkles } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { SeverityBadge } from './SeverityBadge'
import { canGenerateFix, confidenceTone } from '@/utils/mappers'
import { cn } from '@/lib/utils'

/**
 * Détail d'une vulnérabilité réelle.
 *
 * Les actions « Mark false positive » et « Open in editor » de la maquette
 * n'ont pas d'équivalent côté backend : elles sont remplacées par les deux
 * actions réellement disponibles dans Nexus — génération de correctif
 * (`POST /fix/generate`) et copie du JSON brut de la vulnérabilité.
 */
export function FindingDetailDrawer({ finding, onOpenChange, onGenerateFix, onCopyJson, fixLoading }) {
  const fixAvailable = canGenerateFix(finding)

  return (
    <Sheet open={!!finding} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-xl overflow-y-auto bg-card p-6 custom-scrollbar">
        {finding && (
          <>
            <SheetHeader className="p-0">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} label={finding.severityLabel} />
                <span className="text-xs text-muted-foreground">
                  {finding.category} · #{finding.id}
                </span>
              </div>
              <SheetTitle className="mt-2 pr-6 text-left text-lg leading-tight">
                {finding.title}
              </SheetTitle>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono text-muted-foreground">
                <span>
                  {finding.file || 'fichier inconnu'}
                  {finding.line ? `:${finding.line}` : ''}
                  {finding.lineEnd ? `–${finding.lineEnd}` : ''}
                </span>
                {finding.confidence !== null && (
                  <span className={confidenceTone(finding.confidence)}>
                    {finding.confidence}% de confiance
                  </span>
                )}
              </div>
            </SheetHeader>

            {(finding.note || finding.needsManualReview || finding.evidenceMissing) && (
              <div className="mt-5 flex items-start gap-3 rounded-lg border border-medium/30 bg-medium/10 p-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-medium" />
                <div>
                  <div className="text-sm font-medium text-medium">Attention requise</div>
                  <div className="text-xs text-muted-foreground">
                    {finding.note || 'Examen manuel requis (preuve manquante).'}
                  </div>
                </div>
              </div>
            )}

            {finding.snippet && (
              <Section title="Preuve (code source)">
                <pre className="overflow-x-auto rounded-lg border border-border bg-background/60 p-3 text-[12px] leading-relaxed font-mono custom-scrollbar">
                  <code>{finding.snippet}</code>
                </pre>
                {finding.lineReason && (
                  <p className="mt-2 text-[11px] text-muted-foreground">
                    Localisation : {finding.lineReason}
                  </p>
                )}
              </Section>
            )}

            {finding.description && (
              <Section title="Analyse technique">
                <p className="text-sm text-muted-foreground">{finding.description}</p>
              </Section>
            )}

            {finding.impact && (
              <Section title="Impact">
                <p className="text-sm text-muted-foreground">{finding.impact}</p>
              </Section>
            )}

            {finding.fix && (
              <Section title="Correctif recommandé">
                <p className="text-sm text-muted-foreground">{finding.fix}</p>
              </Section>
            )}

            <div className="mt-6 flex flex-wrap gap-2">
              <Button
                className="gap-1.5"
                disabled={!fixAvailable || fixLoading}
                onClick={() => onGenerateFix(finding)}
                title={
                  fixAvailable
                    ? 'Générer un patch pour cette vulnérabilité'
                    : 'Fichier, ligne ou correctif manquant : patch impossible'
                }
              >
                {fixLoading ? (
                  <Loader2 className={cn('h-4 w-4 animate-spin')} />
                ) : (
                  <Sparkles className="h-4 w-4" />
                )}
                {fixLoading ? 'Génération…' : 'Générer le correctif'}
              </Button>
              <Button variant="outline" className="gap-1.5" onClick={() => onCopyJson(finding)}>
                <Copy className="h-4 w-4" /> Copier le JSON
              </Button>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

function Section({ title, children }) {
  return (
    <div className="mt-5">
      <div className="mb-2 text-[11px] uppercase tracking-wider text-muted-foreground">{title}</div>
      {children}
    </div>
  )
}
