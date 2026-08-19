import { useCallback, useEffect, useRef, useState } from 'react'

import { getPreflight } from '@/services/api'

/**
 * Récupère le preflight réel du backend (`GET /scan/preflight`) : statistiques
 * du dépôt, budget effectif du profil, contexte Ollama et avertissements.
 *
 * Ces données remplacent les blocs « Detected stack », « Runtime » et
 * « Preflight notice » qui étaient statiques dans la maquette.
 */
export function usePreflight({ target, profile, mode, ollamaMode, ollamaUrl, enabled = true }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const requestIdRef = useRef(0)

  const load = useCallback(async () => {
    if (!enabled) return
    const requestId = ++requestIdRef.current
    setLoading(true)
    setError(null)
    try {
      const result = await getPreflight({ target, profile, mode, ollamaMode, ollamaUrl })
      if (requestId !== requestIdRef.current) return
      if (result?.success) {
        setData(result.preflight)
      } else {
        setData(null)
        setError(result?.message || 'Preflight indisponible')
      }
    } catch (err) {
      if (requestId !== requestIdRef.current) return
      setData(null)
      setError(err.message || 'Preflight indisponible')
    } finally {
      if (requestId === requestIdRef.current) setLoading(false)
    }
  }, [target, profile, mode, ollamaMode, ollamaUrl, enabled])

  // Récupération depuis l'API : synchronisation avec un système externe.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load()
  }, [load])

  return { data, loading, error, reload: load }
}
