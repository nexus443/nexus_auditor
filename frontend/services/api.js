/**
 * Couche d'accès au backend Nexus.
 *
 * Tous les appels réseau de l'application passent par ce module. Les routes,
 * les payloads et les formats de réponse sont strictement ceux de l'API
 * existante (`backend/backend.py`) — aucune n'a été modifiée pendant la
 * migration graphique.
 */

export const API_URL = '/api'

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request(path, { method = 'GET', body, timeout, signal } = {}) {
  const options = { method, headers: {} }

  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(body)
  }
  if (timeout && signal) {
    options.signal = AbortSignal.any([AbortSignal.timeout(timeout), signal])
  } else if (timeout) {
    options.signal = AbortSignal.timeout(timeout)
  } else if (signal) {
    options.signal = signal
  }

  const res = await fetch(`${API_URL}${path}`, options)
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const payload = await res.json()
      detail = payload?.detail || payload?.message || detail
    } catch {
      /* réponse non JSON : on garde le code HTTP */
    }
    throw new ApiError(detail, res.status)
  }
  return res.json()
}

/** GET /scan/status — état complet du scan courant (ou du dernier scan). */
export const getScanStatus = (scanId, options = {}) =>
  request(scanId ? `/scan/status?scan_id=${encodeURIComponent(scanId)}` : '/scan/status', options)

/**
 * GET /health — sonde de vivacité dédiée du backend.
 * Ne lit ni l'état de scan, ni le disque, ni Ollama : elle mesure uniquement
 * « le service FastAPI répond-il ? », avec un timeout court.
 */
export const pingApi = () => request('/health', { timeout: 3000 })

/** GET /scan/progress — progression légère du scan (payload court, ~1 Ko). */
export const getScanProgress = (options = {}) => request('/scan/progress', options)

/** GET /scan/logs — journal du scan courant uniquement. */
export const getScanLogs = (options = {}) => request('/scan/logs', options)

/** GET /scan/findings — vulnérabilités + compteurs du scan courant. */
export const getScanFindings = (options = {}) => request('/scan/findings', options)

/** GET /scan/stages — rapport d'étapes du pipeline. */
export const getScanStages = (scanId) =>
  request(scanId ? `/scan/stages?scan_id=${encodeURIComponent(scanId)}` : '/scan/stages')

/** POST /scan/start — lance un audit. */
export const startScan = ({ target, profile, mode, ollamaMode, ollamaUrl }) =>
  request('/scan/start', {
    method: 'POST',
    body: {
      target,
      profile,
      mode,
      ollama_mode: ollamaMode,
      ollama_url: ollamaMode === 'remote' ? ollamaUrl : null,
    },
  })

/** POST /scan/stop — demande l'arrêt du scan en cours. */
export const stopScan = () => request('/scan/stop', { method: 'POST' })

/** GET /scan/preflight — statistiques repo, budget effectif et contexte Ollama. */
export const getPreflight = ({ target, profile, mode, ollamaMode, ollamaUrl }) => {
  const params = new URLSearchParams()
  if (target) params.set('target', target)
  if (profile) params.set('profile', profile)
  if (mode) params.set('mode', mode)
  if (ollamaMode) params.set('ollama_mode', ollamaMode)
  if (ollamaMode === 'remote' && ollamaUrl) params.set('ollama_url', ollamaUrl)
  return request(`/scan/preflight?${params.toString()}`)
}

/** POST /ollama/test — teste une URL Ollama et liste les modèles disponibles. */
export const testOllama = (url) => request('/ollama/test', { method: 'POST', body: { url } })

/** GET /history — historique persistant des audits (50 derniers). */
export const getHistory = () => request('/history')

/** GET /profiles — profils de puissance exposés par le backend. */
export const getProfiles = () => request('/profiles')

/** GET /modes — modes de scan exposés par le backend. */
export const getModes = () => request('/modes')

/** POST /fix/generate — génère un patch pour une vulnérabilité. */
export const generateFix = (vulnId) =>
  request('/fix/generate', { method: 'POST', body: { vuln_id: vulnId } })

/** URL de téléchargement d'un patch généré. */
export const patchDownloadUrl = (patchFile) =>
  `${API_URL}/fix/download/${encodeURIComponent(patchFile)}`

/** URL du rapport HTML (GET /export/report). */
export const reportUrl = (scanId) =>
  scanId ? `${API_URL}/export/report?scan_id=${encodeURIComponent(scanId)}` : `${API_URL}/export/report`

/** URL de l'export JSON (GET /export/json). */
export const jsonExportUrl = (scanId) =>
  scanId ? `${API_URL}/export/json?scan_id=${encodeURIComponent(scanId)}` : `${API_URL}/export/json`

export { ApiError }
