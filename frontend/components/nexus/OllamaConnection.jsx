import { useState } from 'react'
import { AlertTriangle, Check, Globe, Loader2, RefreshCw, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { testOllama } from '@/services/api'
import { useNexus } from '@/hooks/useNexus.jsx'
import { cn } from '@/lib/utils'

/**
 * Configuration de la connexion Ollama (fonctionnalité V2.5 de Nexus).
 *
 * Mode « auto » : détection par le backend (localhost:11434 ou Docker).
 * Mode « remote » : URL explicite, testable via `POST /ollama/test`.
 * Les deux valeurs sont persistées dans localStorage, comme auparavant.
 */
export function OllamaConnection({ error, onErrorClear }) {
  const { ollamaMode, setOllamaMode, ollamaUrl, setOllamaUrl, refreshRuntime } = useNexus()
  const [testing, setTesting] = useState(false)
  const [result, setResult] = useState(null)

  const runTest = async () => {
    if (!ollamaUrl.trim()) {
      setResult({ ok: false, message: 'Veuillez entrer une URL' })
      return
    }
    setTesting(true)
    setResult(null)
    try {
      const data = await testOllama(ollamaUrl)
      setResult(data)
      if (data.ok) refreshRuntime()
    } catch {
      setResult({ ok: false, message: 'Backend hors ligne' })
    } finally {
      setTesting(false)
    }
  }

  const selectMode = (mode) => {
    setOllamaMode(mode)
    setResult(null)
    onErrorClear?.()
    if (mode === 'auto') refreshRuntime()
  }

  return (
    <div className="space-y-3">
      <Label className="text-xs uppercase tracking-wider text-muted-foreground">Connexion Ollama</Label>

      <div className="grid grid-cols-2 gap-2">
        <button
          type="button"
          onClick={() => selectMode('auto')}
          className={cn(
            'flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
            ollamaMode === 'auto'
              ? 'border-primary/60 bg-primary/5 text-foreground'
              : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
          )}
        >
          <RefreshCw className="h-3.5 w-3.5" /> Auto
        </button>
        <button
          type="button"
          onClick={() => selectMode('remote')}
          className={cn(
            'flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
            ollamaMode === 'remote'
              ? 'border-primary/60 bg-primary/5 text-foreground'
              : 'border-border bg-background/40 text-muted-foreground hover:text-foreground',
          )}
        >
          <Globe className="h-3.5 w-3.5" /> Distant
        </button>
      </div>

      {ollamaMode === 'auto' ? (
        <p className="text-xs text-muted-foreground">
          Détection automatique par le backend (localhost:11434 ou passerelle Docker).
        </p>
      ) : (
        <div className="space-y-2">
          <Input
            value={ollamaUrl}
            onChange={(event) => {
              setOllamaUrl(event.target.value)
              setResult(null)
              onErrorClear?.()
            }}
            placeholder="192.168.1.50:11434 ou http://…"
            className={cn('font-mono text-sm', error && 'border-critical focus-visible:ring-critical')}
          />
          {error && (
            <p className="flex items-center gap-1 text-xs text-critical">
              <AlertTriangle className="h-3 w-3" /> {error}
            </p>
          )}
          <Button
            variant="outline"
            size="sm"
            className="w-full gap-1.5"
            onClick={runTest}
            disabled={testing || !ollamaUrl.trim()}
          >
            {testing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            {testing ? 'Test en cours…' : 'Tester la connexion'}
          </Button>

          {result && (
            <div
              className={cn(
                'rounded-lg border p-3 text-sm',
                result.ok
                  ? 'border-success/30 bg-success/10 text-success'
                  : 'border-critical/30 bg-critical/10 text-critical',
              )}
            >
              <div className="flex items-center gap-1.5 font-medium">
                {result.ok ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
                {result.message}
              </div>
              {result.models?.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {result.models.slice(0, 5).map((model) => (
                    <span
                      key={model}
                      className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground ring-1 ring-border"
                    >
                      {model}
                    </span>
                  ))}
                  {result.models.length > 5 && (
                    <span className="text-[10px] text-muted-foreground">
                      +{result.models.length - 5} autres
                    </span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
