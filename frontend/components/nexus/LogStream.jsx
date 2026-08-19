import { useEffect, useRef } from 'react'
import { Download, Filter } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { LOG_LEVELS, filterLogs, isMutedLog, logLevel } from '@/utils/mappers'

const LEVEL_STYLES = {
  info: 'text-muted-foreground',
  success: 'text-success',
  warning: 'text-medium',
  error: 'text-critical',
  finding: 'text-primary',
}

const LEVEL_LABELS = {
  all: 'Tous',
  info: 'Info',
  success: 'Succès',
  warning: 'Warn',
  error: 'Erreur',
  finding: 'Détection',
}

/**
 * Journal d'exécution du scan.
 *
 * Reprend l'intégralité des capacités de l'ancienne console : filtrage par
 * niveau, téléchargement du journal complet, copie d'une ligne au clic,
 * autoscroll et mise en retrait des lignes filtrées par le moteur (« 🗑️ Filtered »).
 */
export function LogStream({
  logs = [],
  level = 'all',
  onLevelChange,
  onCopyLine,
  onDownload,
  autoScroll = false,
  className,
}) {
  const endRef = useRef(null)
  const filtered = filterLogs(logs, level)

  useEffect(() => {
    if (autoScroll) endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [autoScroll, filtered.length])

  return (
    <div className={cn('flex flex-col', className)}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1 rounded-md border border-border bg-card/60 p-0.5 text-[11px]">
          <Filter className="ml-1.5 h-3 w-3 text-muted-foreground" />
          {LOG_LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              onClick={() => onLevelChange?.(l)}
              className={cn(
                'rounded px-2 py-0.5 transition-colors',
                level === l ? 'bg-muted text-foreground' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {LEVEL_LABELS[l]}
            </button>
          ))}
        </div>
        {onDownload && (
          <Button variant="outline" size="sm" className="gap-1.5" onClick={onDownload} disabled={logs.length === 0}>
            <Download className="h-3.5 w-3.5" /> Journal
          </Button>
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto custom-scrollbar">
        {filtered.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            {logs.length === 0 ? 'Aucun événement enregistré.' : 'Aucun événement pour ce filtre.'}
          </p>
        ) : (
          filtered.map((log, index) => {
            const lvl = logLevel(log)
            return (
              <div
                key={`${log.time}-${index}`}
                onClick={() => onCopyLine?.(log)}
                className={cn(
                  'flex cursor-pointer gap-3 rounded-md px-2 py-1.5 text-[12px] transition-colors hover:bg-accent/40',
                  isMutedLog(log) && 'opacity-60 italic hover:opacity-100',
                )}
                title="Cliquer pour copier"
              >
                <span className="shrink-0 font-mono text-muted-foreground">{log.time}</span>
                <span className={cn('mt-0.5 shrink-0 font-mono text-[10px] uppercase', LEVEL_STYLES[lvl])}>
                  {lvl}
                </span>
                <span className="min-w-0 flex-1 break-words">{log.msg}</span>
              </div>
            )
          })
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}
