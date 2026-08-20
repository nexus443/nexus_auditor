import { AlertOctagon, Wrench } from 'lucide-react'

import { SectionCard } from './SectionCard'
import { ScoreRing } from './ScoreRing'
import { SeverityBar } from './SeverityBar'
import { SeverityBadge } from './SeverityBadge'
import { Button } from '@/components/ui/button'
import { formatConfidence, sortByRisk, totalFindings } from '@/utils/mappers'
import { cn } from '@/lib/utils'

/**
 * Vue exécutive — logique reprise de l'ancien `components/ExecutiveView.jsx`
 * (top 5 des risques, feuille de route P0/P1/P2, estimation d'effort), portée
 * sur le design system de la nouvelle interface.
 *
 * L'estimation d'effort est la même heuristique que dans l'ancienne interface :
 * elle dérive uniquement de la sévérité réelle des vulnérabilités détectées.
 */
const FIX_MINUTES = { critical: 180, high: 90, medium: 45, low: 20, info: 15 }

const PRIORITIES = [
  {
    key: 'P0',
    label: 'Critique — action immédiate',
    severities: ['critical'],
    tone: 'critical',
  },
  {
    key: 'P1',
    label: 'Élevé — ce sprint',
    severities: ['high'],
    tone: 'high',
  },
  {
    key: 'P2',
    label: 'Moyen / faible — sprint suivant',
    severities: ['medium', 'low', 'info'],
    tone: 'medium',
  },
]

const TONE_CLASSES = {
  critical: { box: 'border-critical/40 bg-critical/5', text: 'text-critical' },
  high: { box: 'border-high/40 bg-high/5', text: 'text-high' },
  medium: { box: 'border-medium/40 bg-medium/5', text: 'text-medium' },
}

export function ExecutiveView({ findings, counts, confidence, target, onSelect }) {
  const total = totalFindings(counts)
  const topRisks = sortByRisk(findings).slice(0, 5)

  const summary =
    counts.critical > 0
      ? `${counts.critical} vulnérabilité(s) critique(s) et ${counts.high} de sévérité haute exigent une correction avant mise en production.`
      : counts.high > 0
        ? `${counts.high} vulnérabilité(s) de sévérité haute à corriger dans le sprint courant.`
        : total > 0
          ? `${total} point(s) d'amélioration identifié(s), aucun risque critique retenu.`
          : "Aucune vulnérabilité retenue selon le niveau d'analyse sélectionné."

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-3">
        <SectionCard className="xl:col-span-2">
          <div className="flex flex-col items-center gap-6 md:flex-row">
            <ScoreRing score={confidence} label="Confiance" suffix="%" />
            <div className="min-w-0 flex-1">
              <div className="text-xs uppercase tracking-wider text-muted-foreground">
                Risque métier
              </div>
              <div className="mt-1 text-lg font-semibold">
                {counts.critical > 0
                  ? 'Élevé — la mise en production devrait être bloquée'
                  : counts.high > 0
                    ? 'Modéré — correction requise avant la prochaine livraison'
                    : 'Maîtrisé'}
              </div>
              <p className="mt-1 text-sm text-muted-foreground">
                {summary}
                {target ? ` Cible auditée : ${target}.` : ''}
              </p>
              <div className="mt-4">
                <SeverityBar counts={counts} />
              </div>
            </div>
          </div>
        </SectionCard>

        <SectionCard
          title="Synthèse"
          actions={<AlertOctagon className="h-4 w-4 text-critical" />}
        >
          <dl className="space-y-2.5 text-sm">
            <Row label="Total" value={total} />
            <Row label="Critical" value={counts.critical} tone="text-critical" />
            <Row label="High" value={counts.high} tone="text-high" />
            <Row label="Medium" value={counts.medium} tone="text-medium" />
            <Row label="Low" value={counts.low} tone="text-low" />
            <Row label="Confiance moyenne" value={formatConfidence(confidence)} />
          </dl>
        </SectionCard>
      </div>

      <SectionCard title="Principaux risques" description="Classés par sévérité puis par confiance">
        {topRisks.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            Aucun risque à prioriser.
          </p>
        ) : (
          <ul className="divide-y divide-border/60">
            {topRisks.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-3 py-3 first:pt-0">
                <SeverityBadge severity={f.severity} label={f.severityLabel} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{f.title}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {f.file || '—'}
                    {f.line ? `:${f.line}` : ''}
                    {f.confidence !== null ? ` · ${f.confidence}% de confiance` : ''}
                  </div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => onSelect?.(f)}>
                  Détail
                </Button>
              </li>
            ))}
          </ul>
        )}
      </SectionCard>

      <SectionCard
        title="Feuille de route de remédiation"
        description="Regroupement par priorité et estimation d'effort"
        actions={<Wrench className="h-4 w-4 text-primary" />}
      >
        <div className="space-y-3">
          {PRIORITIES.map((priority) => {
            const items = findings.filter((f) => priority.severities.includes(f.severity))
            const minutes = items.reduce((sum, f) => sum + (FIX_MINUTES[f.severity] || 30), 0)
            const hours = Math.ceil(minutes / 60)
            const tone = TONE_CLASSES[priority.tone]
            return (
              <div key={priority.key} className={cn('rounded-lg border p-4', tone.box)}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <span className={cn('font-bold', tone.text)}>{priority.key}</span>
                    <span className="ml-2 text-sm text-muted-foreground">{priority.label}</span>
                  </div>
                  <div className="text-right">
                    <div className={cn('text-2xl font-semibold', tone.text)}>{items.length}</div>
                    <div className="text-xs text-muted-foreground">
                      {items.length > 0 ? `~${hours} h estimées` : '—'}
                    </div>
                  </div>
                </div>
                {items.length > 0 && (
                  <div className="mt-2 truncate text-xs text-muted-foreground">
                    {items.slice(0, 3).map((f) => f.title).join(' • ')}
                    {items.length > 3 && ` • +${items.length - 3} autres`}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </SectionCard>
    </div>
  )
}

function Row({ label, value, tone }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={cn('font-mono font-semibold', tone)}>{value}</dd>
    </div>
  )
}
