import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

import * as api from '@/services/api'
import { useToasts } from '@/components/Toast.jsx'
import {
  mapApiVulnsToUi,
  mapHistoryToUi,
  mapStageReport,
  scanStatusPill,
  statsToSeverityCounts,
} from '@/utils/mappers'

const NexusContext = createContext(null)

/** Fréquence de polling de l'état du scan (identique à l'ancienne interface). */
const STATUS_POLL_MS = 1000
/** Fréquence de la sonde de santé de l'API (identique à l'ancienne interface). */
const HEALTH_POLL_MS = 30000

const EMPTY_STATUS = {
  id: null,
  is_scanning: false,
  progress: 0,
  estimated_time: 'En attente',
  current_file: '',
  current_stage: 'idle',
  stage_report: null,
  stats: { critical: 0, high: 0, medium: 0, low: 0, files: 0, skipped: 0 },
  logs: [],
  vulnerabilities: [],
  confidence_score: 0,
  target_dir: null,
  profile: null,
  mode: null,
  preflight: {},
  telemetry: null,
}

const readStored = (key, fallback) => {
  try {
    const value = localStorage.getItem(key)
    return value === null ? fallback : value
  } catch {
    return fallback
  }
}

const writeStored = (key, value) => {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* localStorage indisponible (mode privé) : préférence non persistée */
  }
}

export function NexusProvider({ children }) {
  const toast = useToasts()
  const navigate = useNavigate()
  const location = useLocation()

  // --- Thème (bascule clair/sombre conservée de l'ancienne interface) -------
  const [theme, setTheme] = useState(() => readStored('theme', 'dark'))

  // --- Configuration d'audit, persistée localement -------------------------
  const [target, setTarget] = useState(() => readStored('nexusTarget', ''))
  const [profile, setProfile] = useState(() => readStored('nexusProfile', 'balanced'))
  const [scanMode, setScanMode] = useState(() => readStored('nexusMode', 'deep'))
  const [ollamaMode, setOllamaMode] = useState(() => readStored('ollamaMode', 'auto'))
  const [ollamaUrl, setOllamaUrl] = useState(() => readStored('ollamaUrl', ''))

  // --- État du scan --------------------------------------------------------
  const [status, setStatus] = useState(EMPTY_STATUS)
  const [statusLoading, setStatusLoading] = useState(true)
  const [statusError, setStatusError] = useState(null)

  // --- Historique ----------------------------------------------------------
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState(null)

  // --- Santé des services --------------------------------------------------
  const [health, setHealth] = useState({ api: 'unknown', lastCheck: null })

  // --- Catalogue backend (profils / modes) ---------------------------------
  const [catalog, setCatalog] = useState({ profiles: null, modes: null })

  // --- Preflight « runtime » partagé (endpoint Ollama, budget, modèles) ----
  const [runtime, setRuntime] = useState({ data: null, loading: true, error: null })

  // --- Divers --------------------------------------------------------------
  const [fixLoadingId, setFixLoadingId] = useState(null)
  const [starting, setStarting] = useState(false)

  // Chemin courant conservé dans une ref : le polling doit le lire sans se
  // réabonner à chaque navigation.
  const locationRef = useRef(location.pathname)
  useEffect(() => {
    locationRef.current = location.pathname
  }, [location.pathname])

  // Thème : attribut sur <html>, lu par les tokens CSS.
  useEffect(() => {
    writeStored('theme', theme)
    document.documentElement.setAttribute('data-theme', theme)
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])

  useEffect(() => writeStored('nexusTarget', target), [target])
  useEffect(() => writeStored('nexusProfile', profile), [profile])
  useEffect(() => writeStored('nexusMode', scanMode), [scanMode])
  useEffect(() => writeStored('ollamaMode', ollamaMode), [ollamaMode])
  useEffect(() => writeStored('ollamaUrl', ollamaUrl), [ollamaUrl])

  // --- Sonde de santé de l'API --------------------------------------------
  useEffect(() => {
    let cancelled = false
    const check = async () => {
      try {
        await api.pingApi()
        if (!cancelled) setHealth({ api: 'online', lastCheck: Date.now() })
      } catch {
        if (!cancelled) setHealth({ api: 'offline', lastCheck: Date.now() })
      }
    }
    check()
    const interval = setInterval(check, HEALTH_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const data = await api.getHistory()
      setHistory(Array.isArray(data) ? data : [])
      setHistoryError(null)
    } catch (error) {
      setHistoryError(error.message || 'Historique indisponible')
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  const refreshStatus = useCallback(async () => {
    try {
      const data = await api.getScanStatus()
      setStatus((previous) => ({ ...EMPTY_STATUS, ...previous, ...data }))
      setStatusError(null)
      return data
    } catch (error) {
      setStatusError(error.message || 'Backend injoignable')
      return null
    } finally {
      setStatusLoading(false)
    }
  }, [])

  /**
   * Preflight partagé : contexte Ollama et budget effectif du profil courant.
   * Une seule requête au démarrage (et à la demande) — la page « Nouveau scan »
   * en relance une avec la cible réellement saisie.
   */
  const refreshRuntime = useCallback(async () => {
    setRuntime((previous) => ({ ...previous, loading: true }))
    try {
      const result = await api.getPreflight({
        profile,
        mode: scanMode,
        ollamaMode,
        ollamaUrl,
      })
      if (result?.success) {
        setRuntime({ data: result.preflight, loading: false, error: null })
      } else {
        setRuntime({ data: null, loading: false, error: result?.message || 'Preflight indisponible' })
      }
    } catch (error) {
      setRuntime({ data: null, loading: false, error: error.message || 'Preflight indisponible' })
    }
  }, [profile, scanMode, ollamaMode, ollamaUrl])

  // Chargement initial : état du scan, historique, catalogue backend, runtime.
  // Ces appels réseau alimentent l'état depuis un système externe (l'API) :
  // c'est un cas légitime de fetch dans un effet, sans librairie de data-fetching.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshStatus()
    refreshHistory()
    Promise.allSettled([api.getProfiles(), api.getModes()]).then(([profiles, modes]) => {
      setCatalog({
        profiles: profiles.status === 'fulfilled' ? profiles.value : null,
        modes: modes.status === 'fulfilled' ? modes.value : null,
      })
    })
  }, [refreshStatus, refreshHistory])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshRuntime()
  }, [refreshRuntime])

  // --- Polling de l'état du scan ------------------------------------------
  // On interroge l'API tant qu'un scan est actif. Un scan terminé (100 %) ou
  // arrêté (`terminal_state` renseigné) coupe le polling.
  const isPolling =
    Boolean(status.is_scanning) ||
    (status.progress > 0 && status.progress < 100 && !status.stage_report?.terminal_state)

  useEffect(() => {
    if (!isPolling) return undefined

    const interval = setInterval(async () => {
      const data = await refreshStatus()
      if (!data) return
      // Fin de scan : rafraîchit l'historique et bascule sur les résultats si
      // l'utilisateur regardait le scan en direct (comportement d'origine).
      if (!data.is_scanning && data.progress === 100) {
        refreshHistory()
        if (locationRef.current === '/scan/live') navigate('/results')
      }
    }, STATUS_POLL_MS)

    return () => clearInterval(interval)
  }, [isPolling, refreshStatus, refreshHistory, navigate])

  // --- Actions -------------------------------------------------------------

  /**
   * Lance un audit. Reprend la validation de l'ancienne interface : cible
   * obligatoire, URL Ollama obligatoire en mode distant.
   * Retourne `{ ok, errors }` pour que la page puisse afficher les erreurs
   * de champ.
   */
  const startScan = useCallback(
    async (overrides = {}) => {
      const payload = {
        target: overrides.target ?? target,
        profile: overrides.profile ?? profile,
        mode: overrides.mode ?? scanMode,
        ollamaMode: overrides.ollamaMode ?? ollamaMode,
        ollamaUrl: overrides.ollamaUrl ?? ollamaUrl,
      }

      const errors = {}
      if (!payload.target || !payload.target.trim()) {
        errors.target = 'Veuillez entrer une cible (URL Git ou chemin local)'
      }
      if (payload.ollamaMode === 'remote' && !payload.ollamaUrl.trim()) {
        errors.ollamaUrl = 'URL Ollama requise en mode distant'
      }
      if (Object.keys(errors).length > 0) {
        toast.error(errors.target || errors.ollamaUrl)
        return { ok: false, errors }
      }

      setStarting(true)
      try {
        const result = await api.startScan(payload)
        if (result && result.success === false) {
          toast.error(result.msg || "Impossible de lancer l'audit")
          return { ok: false, errors: {} }
        }
        setStatus((previous) => ({
          ...previous,
          id: result?.scan_id ?? previous.id,
          is_scanning: true,
          progress: 1,
          vulnerabilities: [],
          logs: [],
          stats: { critical: 0, high: 0, medium: 0, low: 0, files: 0, skipped: 0 },
        }))
        toast.success('Scan lancé avec succès')
        navigate('/scan/live')
        return { ok: true, errors: {} }
      } catch {
        toast.error('Backend hors ligne - vérifiez que le serveur est démarré')
        return { ok: false, errors: {} }
      } finally {
        setStarting(false)
      }
    },
    [target, profile, scanMode, ollamaMode, ollamaUrl, toast, navigate],
  )

  /** Arrête le scan en cours et stoppe immédiatement le polling. */
  const stopScan = useCallback(async () => {
    try {
      await api.stopScan()
      // Coupe le polling immédiatement (comportement de l'ancienne interface),
      // puis récupère une dernière fois l'état final côté backend.
      setStatus((previous) => ({ ...previous, is_scanning: false, should_stop: true }))
      toast.info('Arrêt du scan demandé')
      await refreshStatus()
      refreshHistory()
    } catch {
      toast.error("Impossible d'arrêter le scan")
    }
  }, [toast, refreshStatus, refreshHistory])

  /** Génère un patch pour une vulnérabilité et déclenche son téléchargement. */
  const generateFix = useCallback(
    async (vulnId) => {
      setFixLoadingId(vulnId)
      try {
        const data = await api.generateFix(vulnId)
        if (data.success) {
          toast.success(`Patch généré: ${data.patch_file}`, 8000)
          window.open(api.patchDownloadUrl(data.patch_file), '_blank')
        } else {
          toast.error(`Échec génération patch: ${data.error || 'erreur inconnue'}`)
        }
        return data
      } catch (error) {
        toast.error(error.message || 'Erreur lors de la génération du patch')
        return null
      } finally {
        setFixLoadingId(null)
      }
    },
    [toast],
  )

  const downloadReport = useCallback((scanId) => {
    window.open(api.reportUrl(scanId), '_blank')
  }, [])

  const downloadJson = useCallback((scanId) => {
    window.open(api.jsonExportUrl(scanId), '_blank')
  }, [])

  // --- Données dérivées ----------------------------------------------------

  const findings = useMemo(() => mapApiVulnsToUi(status.vulnerabilities), [status.vulnerabilities])
  const severityCounts = useMemo(
    () => statsToSeverityCounts(status.stats, findings),
    [status.stats, findings],
  )
  const stageReport = useMemo(() => mapStageReport(status.stage_report), [status.stage_report])
  const historyEntries = useMemo(() => mapHistoryToUi(history), [history])
  const scanState = useMemo(() => scanStatusPill(status), [status])

  const value = useMemo(
    () => ({
      // configuration
      theme,
      setTheme,
      target,
      setTarget,
      profile,
      setProfile,
      scanMode,
      setScanMode,
      ollamaMode,
      setOllamaMode,
      ollamaUrl,
      setOllamaUrl,
      catalog,
      runtime,
      refreshRuntime,
      // état
      status,
      statusLoading,
      statusError,
      findings,
      severityCounts,
      stageReport,
      scanState,
      isScanning: Boolean(status.is_scanning),
      hasResults: findings.length > 0 || status.progress === 100,
      health,
      history: historyEntries,
      historyLoading,
      historyError,
      fixLoadingId,
      starting,
      // actions
      startScan,
      stopScan,
      generateFix,
      refreshStatus,
      refreshHistory,
      downloadReport,
      downloadJson,
    }),
    [
      theme,
      target,
      profile,
      scanMode,
      ollamaMode,
      ollamaUrl,
      catalog,
      runtime,
      refreshRuntime,
      status,
      statusLoading,
      statusError,
      findings,
      severityCounts,
      stageReport,
      scanState,
      health,
      historyEntries,
      historyLoading,
      historyError,
      fixLoadingId,
      starting,
      startScan,
      stopScan,
      generateFix,
      refreshStatus,
      refreshHistory,
      downloadReport,
      downloadJson,
    ],
  )

  return <NexusContext.Provider value={value}>{children}</NexusContext.Provider>
}

export function useNexus() {
  const context = useContext(NexusContext)
  if (!context) {
    throw new Error('useNexus doit être utilisé à l\'intérieur de <NexusProvider>')
  }
  return context
}
