/**
 * Couche d'adaptation entre les structures renvoyées par le backend Nexus et
 * celles attendues par les composants de la nouvelle interface.
 *
 * Le backend reste la source de vérité : rien n'y est modifié, tout est
 * normalisé ici.
 */

/** Sévérités du design system (minuscules), dans l'ordre décroissant de gravité. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

/**
 * Le backend renvoie "Critical" | "High" | "Medium" | "Low" | "Unknown".
 * Le design system utilise des clés minuscules et traite "Unknown" comme "info".
 */
export function toUiSeverity(severity) {
  const value = String(severity || '').trim().toLowerCase()
  if (value.startsWith('crit')) return 'critical'
  if (value.startsWith('high')) return 'high'
  if (value.startsWith('med')) return 'medium'
  if (value.startsWith('low')) return 'low'
  return 'info'
}

/** Inverse de `toUiSeverity`, pour les libellés lisibles. */
export function toBackendSeverity(uiSeverity) {
  return { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Unknown' }[
    uiSeverity
  ]
}

export function severityRank(uiSeverity) {
  return SEVERITY_RANK[uiSeverity] || 0
}

/** La confiance backend est un nombre 0-100 ; l'UI affiche un palier. */
export function confidenceLabel(confidence) {
  const value = Number(confidence)
  if (!Number.isFinite(value)) return '—'
  if (value >= 70) return 'High'
  if (value >= 40) return 'Medium'
  return 'Low'
}

/**
 * Confiance globale du scan : `null` signifie « non calculée » (la corrélation
 * n'a jamais abouti — timeout, échec ou annulation). On n'affiche jamais 0 %
 * à la place : 0 % voudrait dire « calculée, et nulle ».
 */
export function hasConfidence(confidence) {
  return confidence !== null && confidence !== undefined && Number.isFinite(Number(confidence))
}

export function formatConfidence(confidence) {
  return hasConfidence(confidence) ? `${Math.round(Number(confidence))}%` : 'Non calculée'
}

export function confidenceTone(confidence) {
  const value = Number(confidence)
  if (!Number.isFinite(value)) return 'text-muted-foreground'
  if (value >= 70) return 'text-success'
  if (value >= 40) return 'text-medium'
  return 'text-critical'
}

/**
 * Normalise une vulnérabilité backend vers le modèle « finding » de l'UI.
 * Les champs bruts sont conservés dans `raw` (export JSON, génération de patch).
 */
export function mapApiVulnToUi(vuln) {
  if (!vuln) return null

  const file = vuln.file || vuln.filepath || ''
  const lineStart = vuln.line ?? vuln.line_start ?? null
  const lineEnd = vuln.line_end ?? null
  const hasLine = lineStart !== null && lineStart !== undefined && String(lineStart) !== 'N/A'

  return {
    id: vuln.id,
    title: vuln.title || vuln.type || 'Vulnérabilité',
    severity: toUiSeverity(vuln.severity),
    severityLabel: vuln.severity || 'Unknown',
    file,
    filepath: vuln.filepath || vuln.file || '',
    line: hasLine ? lineStart : null,
    lineEnd: lineEnd && String(lineEnd) !== 'N/A' ? lineEnd : null,
    lineReason: vuln.line_reason || null,
    category: vuln.type || 'GENERIC',
    confidence: Number.isFinite(Number(vuln.confidence)) ? Number(vuln.confidence) : null,
    snippet: vuln.snippet && vuln.snippet !== 'Code non disponible' ? vuln.snippet : '',
    evidence: vuln.evidence || '',
    description: vuln.description || '',
    impact: vuln.impact && vuln.impact !== 'Non évalué' ? vuln.impact : '',
    fix: vuln.fix && vuln.fix !== 'Pas de correctif proposé.' ? vuln.fix : '',
    note: vuln.note || '',
    needsManualReview: Boolean(vuln.needs_manual_review),
    evidenceMissing: Boolean(vuln.evidence_missing),
    timestamp: vuln.timestamp || null,
    raw: vuln,
  }
}

export function mapApiVulnsToUi(vulnerabilities) {
  return (vulnerabilities || []).map(mapApiVulnToUi).filter(Boolean)
}

/**
 * Un patch ne peut être généré que si le backend dispose d'un fichier, d'une
 * ligne et d'un correctif : même règle que l'ancienne interface.
 */
export function canGenerateFix(finding) {
  return Boolean(finding && finding.file && finding.line && finding.fix)
}

/** Compte les findings par sévérité UI (pour SeverityBar / StatCard). */
export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of findings || []) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1
  }
  return counts
}

/**
 * Les compteurs officiels viennent de `status.stats` (backend). On les
 * complète avec les findings « Unknown » qui n'entrent dans aucun compteur.
 */
export function statsToSeverityCounts(stats, findings) {
  const fromFindings = countBySeverity(findings)
  return {
    critical: stats?.critical ?? fromFindings.critical,
    high: stats?.high ?? fromFindings.high,
    medium: stats?.medium ?? fromFindings.medium,
    low: stats?.low ?? fromFindings.low,
    info: fromFindings.info,
  }
}

export function totalFindings(counts) {
  return Object.values(counts || {}).reduce((sum, value) => sum + (value || 0), 0)
}

/** Tri par gravité puis par confiance décroissante. */
export function sortByRisk(findings) {
  return [...(findings || [])].sort((a, b) => {
    const bySeverity = severityRank(b.severity) - severityRank(a.severity)
    if (bySeverity !== 0) return bySeverity
    return (b.confidence || 0) - (a.confidence || 0)
  })
}

const STAGE_DESCRIPTIONS = {
  normalize: 'Préparation de la cible et détection des fichiers',
  index: 'Indexation et cartographie du code',
  analyze: 'Analyse IA des fichiers',
  correlate: 'Corrélation inter-fichiers et déduplication',
  report: 'Génération des rapports',
}

const STAGE_LABELS = {
  normalize: 'Normalize',
  index: 'Index',
  analyze: 'Analyze',
  correlate: 'Correlate',
  report: 'Report',
}

/**
 * Transforme `status.stage_report` (backend) en liste d'étapes + index courant
 * pour `StageTimeline`. Aucune heuristique sur la progression n'est utilisée :
 * l'état réel du pipeline (y compris failed/cancelled/skipped sur interruption)
 * est désormais disponible côté API.
 */
export function mapStageReport(stageReport) {
  const sequence = stageReport?.sequence?.length
    ? stageReport.sequence
    : ['normalize', 'index', 'analyze', 'correlate', 'report']

  const stageStatus = stageReport?.stage_status || {}
  const stages = sequence.map((key) => ({
    key,
    label: STAGE_LABELS[key] || key,
    description: STAGE_DESCRIPTIONS[key] || '',
    status: stageStatus[key] || 'pending',
  }))

  const terminal = stageReport?.terminal_state || null
  // Stage interrompu : champ dédié depuis la refonte du state machine ; pour
  // les états persistés plus anciens, on retombe sur le stage resté "active".
  const interruptedStage =
    stageReport?.interrupted_stage ||
    (terminal && terminal !== 'completed'
      ? sequence.find((key) => ['active', 'failed', 'cancelled'].includes(stageStatus[key]))
      : null) ||
    null
  // Sur interruption, `current` contient le jeton terminal (failed/timeout/…),
  // pas un nom de stage : on retombe alors sur le stage interrompu enregistré.
  let currentIndex = sequence.indexOf(stageReport?.current)
  if (currentIndex < 0 && interruptedStage) {
    currentIndex = sequence.indexOf(interruptedStage)
  }
  if (currentIndex < 0) {
    currentIndex = terminal === 'completed' ? sequence.length : 0
  }
  if (terminal === 'completed') currentIndex = sequence.length

  return { stages, currentIndex, terminal, interruptedStage }
}

/**
 * Niveau d'un log. Le backend fournit `type` (info/success/warning/error) ;
 * on ajoute le niveau « finding » pour les détections, repéré comme dans
 * l'ancienne interface (préfixe 🚨).
 */
export function logLevel(log) {
  const type = String(log?.type || 'info').toLowerCase()
  const msg = String(log?.msg || '')
  if (msg.includes('🚨')) return 'finding'
  if (type === 'error') return 'error'
  if (type === 'warning' || msg.includes('⚠️')) return 'warning'
  if (type === 'success') return 'success'
  return 'info'
}

export const LOG_LEVELS = ['all', 'info', 'success', 'warning', 'error', 'finding']

export function filterLogs(logs, level) {
  if (!level || level === 'all') return logs || []
  return (logs || []).filter((log) => logLevel(log) === level)
}

/** Un log « filtré » par le moteur est affiché en retrait (comportement V3.1). */
export function isMutedLog(log) {
  return String(log?.msg || '').includes('🗑️ Filtered')
}

const STATUS_PILL_VALUES = ['completed', 'failed', 'running', 'stopped', 'timeout', 'cancelled']

/** États terminaux non aboutis : les détections y sont partielles. */
export const INTERRUPTED_STATES = ['timeout', 'failed', 'cancelled']

/**
 * Normalise une entrée d'historique. Le fichier `audit_history.json` contient
 * deux générations d'entrées (avec `score` pour les plus anciennes, avec
 * `confidence_score` / `duration_seconds` / `telemetry` pour les récentes).
 */
export function mapHistoryEntryToUi(entry) {
  if (!entry) return null

  const stats = entry.stats || {}
  const counts = {
    critical: stats.critical || 0,
    high: stats.high || 0,
    medium: stats.medium || 0,
    low: stats.low || 0,
    info: 0,
  }

  const status = STATUS_PILL_VALUES.includes(entry.status) ? entry.status : 'completed'
  const confidence =
    entry.confidence_score !== undefined && entry.confidence_score !== null
      ? Number(entry.confidence_score)
      : entry.score !== undefined && entry.score !== null
        ? Number(entry.score)
        : null

  return {
    id: entry.id || '—',
    target: entry.target || '—',
    date: entry.date || null,
    profile: entry.profile || null,
    mode: entry.mode || null,
    files: stats.files || 0,
    skipped: stats.skipped || 0,
    counts,
    total: counts.critical + counts.high + counts.medium + counts.low,
    confidence: Number.isFinite(confidence) ? confidence : null,
    durationSeconds: Number.isFinite(Number(entry.duration_seconds))
      ? Number(entry.duration_seconds)
      : null,
    successfulAnalyses: entry.successful_analyses ?? null,
    failedAnalyses: entry.failed_analyses ?? null,
    llmBudget: entry.llm_budget || null,
    telemetry: entry.telemetry || null,
    status,
    raw: entry,
  }
}

export function mapHistoryToUi(history) {
  return (Array.isArray(history) ? history : []).map(mapHistoryEntryToUi).filter(Boolean)
}

/**
 * État canonique du scan courant :
 * 'idle' | 'running' | 'completed' | 'failed' | 'timeout' | 'cancelled'.
 *
 * Source de vérité : le champ `lifecycle` calculé par le backend. Le fallback
 * (états persistés avant l'introduction de `lifecycle`) ne dérive JAMAIS un
 * succès de `!is_scanning` ni de la progression : seul
 * `terminal_state === "completed"` signifie « audit complet ».
 */
export function scanStatusPill(status) {
  const lifecycle = status?.lifecycle
  if (STATUS_PILL_VALUES.includes(lifecycle) || lifecycle === 'idle') {
    return lifecycle === 'stopped' ? 'cancelled' : lifecycle
  }
  if (status?.is_scanning) return 'running'
  const terminal = status?.stage_report?.terminal_state
  if (terminal === 'completed') return 'completed'
  if (terminal === 'timeout') return 'timeout'
  if (terminal === 'stopped' || terminal === 'cancelled') return 'cancelled'
  if (terminal === 'failed' || terminal === 'error') return 'failed'
  return status?.id && (status?.progress || 0) > 0 ? 'cancelled' : 'idle'
}
