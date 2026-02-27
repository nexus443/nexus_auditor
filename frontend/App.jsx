import React, { useState, useEffect, useRef } from 'react';
import {
   Shield, Search, Activity, FileText, Terminal, AlertTriangle,
   CheckCircle, XCircle, ChevronRight, Bug, X, Code, Clock,
   Download, History, Zap, Layers, Server, Sun, Moon, Filter, ChevronDown,
   TrendingUp, Wrench, BookOpen, GitCompare, Sparkles, AlertOctagon, Copy,
   Database, Cpu, RotateCcw, ArrowLeft, Wifi, WifiOff
} from 'lucide-react';
import { useToasts } from './components/Toast.jsx';
import ExecutiveView from './components/ExecutiveView.jsx';

const API_URL = "/api";

// PIPELINE STAGES (static)
const PIPELINE_STAGES = [
   { key: 'normalize', label: 'Normalize', icon: '📋', idx: 1 },
   { key: 'index',     label: 'Index',     icon: '🔍', idx: 2 },
   { key: 'analyze',   label: 'Analyze',   icon: '🧠', idx: 3 },
   { key: 'correlate', label: 'Correlate', icon: '🔗', idx: 4 },
   { key: 'report',    label: 'Report',    icon: '📊', idx: 5 },
];

// LOG CLASSIFICATION
// Error = runtime failures (timeout, http5xx, exception, unreachable)
// Warn  = findings or policy warnings
// Info  = normal progress
const LOG_RUNTIME_ERROR_TOKENS = ['timeout', 'http 5', 'http5', 'exception', 'unreachable', 'connection refused', 'traceback', 'oserror', 'ioerror'];
const LOG_WARN_TOKENS = ['⚠️', 'warning', '⚠', 'filtered', 'prudent', 'skipped', 'excluded'];
const LOG_ERROR_TOKENS = ['❌', 'error', '🚨', 'critical', 'failed', 'failure'];

function classifyLog(log) {
   const msg = (log.msg || '').toLowerCase();
   if (LOG_RUNTIME_ERROR_TOKENS.some(t => msg.includes(t))) return 'error';
   if (LOG_ERROR_TOKENS.some(t => msg.includes(t))) return 'error';
   if (LOG_WARN_TOKENS.some(t => msg.includes(t))) return 'warn';
   if (log.type === 'success') return 'info';
   return 'info';
}

// Static color classes for log levels
const LOG_COLOR_CLASSES = {
   error: 'text-red-400',
   warn:  'text-yellow-400',
   info:  'text-slate-300',
};

// Log filter button definitions (static)
const LOG_FILTER_LEVELS = [
   { key: 'all',   label: 'ALL',   activeClass: 'bg-slate-700 text-white' },
   { key: 'info',  label: 'INFO',  activeClass: 'bg-indigo-600 text-white' },
   { key: 'warn',  label: 'WARN',  activeClass: 'bg-yellow-600 text-white' },
   { key: 'error', label: 'ERROR', activeClass: 'bg-red-600 text-white' },
];

// SEVERITY STYLES 
const SEVERITY_STYLES = {
   CRITICAL: { badge: 'bg-red-500/10 text-red-500 border-red-500/20', icon: AlertOctagon, color: 'text-red-500', border: 'border-red-500' },
   HIGH: { badge: 'bg-orange-500/10 text-orange-500 border-orange-500/20', icon: AlertTriangle, color: 'text-orange-500', border: 'border-orange-500' },
   MEDIUM: { badge: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20', icon: Activity, color: 'text-yellow-500', border: 'border-yellow-500' },
   LOW: { badge: 'bg-blue-500/10 text-blue-500 border-blue-500/20', icon: CheckCircle, color: 'text-blue-500', border: 'border-blue-500' },
};

// MODE STYLES (static to prevent Tailwind purge)
const MODE_STYLES = {
   rapid: {
      active: 'border-emerald-500 bg-emerald-500/10',
      iconActive: 'text-emerald-400',
      iconInactive: 'text-slate-400'
   },
   deep: {
      active: 'border-indigo-500 bg-indigo-500/10',
      iconActive: 'text-indigo-400',
      iconInactive: 'text-slate-400'
   },
   devsecops: {
      active: 'border-orange-500 bg-orange-500/10',
      iconActive: 'text-orange-400',
      iconInactive: 'text-slate-400'
   }
};

export default function App() {
   const toast = useToasts();
   const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark');

   // VIEW STATE (new)
   const [view, setView] = useState('config'); // 'config' | 'preflight' | 'running' | 'results'

   // Preflight state
   const [preflightData, setPreflightData] = useState(null);
   const [preflightLoading, setPreflightLoading] = useState(false);
   const [preflightError, setPreflightError] = useState(null);

   const [activeTab, setActiveTab] = useState('scan');
   const [target, setTarget] = useState("");
   const [profile, setProfile] = useState("balanced");
   const [scanMode, setScanMode] = useState("deep");
   const [showLogs, setShowLogs] = useState(false); // V3.1: Log permanence
   const [status, setStatus] = useState({
      is_scanning: false,
      progress: 0,
      estimated_time: "En attente",
      current_file: "",
      stats: { critical: 0, high: 0, medium: 0, low: 0, files: 0 },
      logs: [],
      vulnerabilities: [],
      confidence_score: 0
   });

   // Results Explorer State
   const [selectedVulnId, setSelectedVulnId] = useState(null);
   const [resultsFilter, setResultsFilter] = useState('ALL');
   const [resultsSearch, setResultsSearch] = useState('');
   const [resultsViewMode, setResultsViewMode] = useState('technical'); // 'executive' | 'technical'
   const [resultsGroupBy, setResultsGroupBy] = useState('flat'); // 'flat' | 'file'
   const [autoFixError, setAutoFixError] = useState(null); // null | string
   const [autoFixSuccess, setAutoFixSuccess] = useState(null); // null | patch_file

   // Legacy states (kept for compatibility)
   const [searchQuery, setSearchQuery] = useState("");
   const [selectedSeverities, setSelectedSeverities] = useState([]);
   const [selectedFiles, setSelectedFiles] = useState([]);
   const [showFilters, setShowFilters] = useState(false);
   const [selectedVuln, setSelectedVuln] = useState(null);
   const [expandedCards, setExpandedCards] = useState(new Set());
   const [history, setHistory] = useState([]);
   const [showHistory, setShowHistory] = useState(false);
   const [historySearch, setHistorySearch] = useState('');
   const [autoFixLoading, setAutoFixLoading] = useState(null);
   const logEndRef = useRef(null);
   const logContainerRef = useRef(null);
   const logFollowRef = useRef(true);          // mutable flag — no re-render on change
   const [showScrollBack, setShowScrollBack] = useState(false);

   // Ollama Connection States (V2.5)
   const [ollamaMode, setOllamaMode] = useState(() => localStorage.getItem('ollamaMode') || 'auto');
   const [ollamaUrl, setOllamaUrl] = useState(() => localStorage.getItem('ollamaUrl') || '');
   const [ollamaTesting, setOllamaTesting] = useState(false);
   const [ollamaTestResult, setOllamaTestResult] = useState(null);

   // Validation errors
   const [targetError, setTargetError] = useState('');
   const [ollamaUrlError, setOllamaUrlError] = useState('');

   // Service health
   const [serviceHealth, setServiceHealth] = useState({
      api: 'unknown', // 'online' | 'offline' | 'unknown'
      ollama: 'unknown',
      lastCheck: null
   });

   // Log filtering / search for advanced log viewer
   const [logFilter, setLogFilter] = useState('all'); // 'all' | 'info' | 'warn' | 'error'
   const [logSearch, setLogSearch] = useState('');

   // Running diagnostics
   const [pollingState, setPollingState] = useState('idle'); // 'ok' | 'reconnecting' | 'idle'
   const [stageTimers, setStageTimers] = useState({}); // { stageName: startTimestamp }
   const [lastStage, setLastStage] = useState(null);
   const [stuckWarning, setStuckWarning] = useState(null); // null | { stage, elapsed }

   // Stuck thresholds per profile (seconds)
   const STUCK_THRESHOLDS = { eco: 90, balanced: 180, elite: 300, titan: 600 };

   useEffect(() => {
      localStorage.setItem('theme', theme);
      document.documentElement.setAttribute('data-theme', theme);
   }, [theme]);

   // Check service health on mount and periodically
   useEffect(() => {
      const checkHealth = async () => {
         try {
            const res = await fetch(`${API_URL}/scan/status`, { signal: AbortSignal.timeout(3000) });
            if (res.ok) {
               setServiceHealth(prev => ({ ...prev, api: 'online', lastCheck: Date.now() }));
            } else {
               setServiceHealth(prev => ({ ...prev, api: 'offline', lastCheck: Date.now() }));
            }
         } catch (e) {
            setServiceHealth(prev => ({ ...prev, api: 'offline', lastCheck: Date.now() }));
         }
      };

      checkHealth();
      const interval = setInterval(checkHealth, 30000); // Every 30s
      return () => clearInterval(interval);
   }, []);

   useEffect(() => {
      if (!status.is_scanning && status.progress === 0) return;

      let isCancelled = false;
      let backoff = 1000;

      const poll = async () => {
         if (isCancelled) return;
         try {
            const res = await fetch(`${API_URL}/scan/status`, { signal: AbortSignal.timeout(5000) });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            if (!isCancelled) {
               setStatus(data);
               setPollingState('ok');
               backoff = 1000; // reset backoff on success

               // Stage tracking for stuck detector
               const currentStage = data.current_stage || null;
               setLastStage(prev => {
                  if (currentStage && currentStage !== prev) {
                     setStageTimers(t => ({ ...t, [currentStage]: Date.now() }));
                     setStuckWarning(null);
                  }
                  return currentStage;
               });

               // Auto-switch to results view when scan completes
               if (!data.is_scanning && data.progress === 100) {
                  setView('results');
               }

               if (view === 'running') scrollToBottom();
            }
         } catch (e) {
            if (!isCancelled) {
               setPollingState('reconnecting');
               backoff = Math.min(backoff * 2, 8000);
            }
         }
         if (!isCancelled) setTimeout(poll, backoff);
      };

      poll();
      return () => { isCancelled = true; };
   // eslint-disable-next-line react-hooks/exhaustive-deps
   }, [status.is_scanning]);

   // Stuck detector: check every 5s if current stage has stalled
   useEffect(() => {
      if (!status.is_scanning) return;
      const threshold = (STUCK_THRESHOLDS[profile] || 180) * 1000;
      const interval = setInterval(() => {
         setStageTimers(timers => {
            if (lastStage && timers[lastStage]) {
               const elapsed = Date.now() - timers[lastStage];
               if (elapsed > threshold) {
                  setStuckWarning({ stage: lastStage, elapsed: Math.round(elapsed / 1000) });
               }
            }
            return timers;
         });
      }, 5000);
      return () => clearInterval(interval);
   }, [status.is_scanning, lastStage, profile]);

   useEffect(() => {
      loadHistory();
   }, []);

   // Persist Ollama config
   useEffect(() => {
      localStorage.setItem('ollamaMode', ollamaMode);
   }, [ollamaMode]);

   useEffect(() => {
      localStorage.setItem('ollamaUrl', ollamaUrl);
   }, [ollamaUrl]);

   const loadHistory = async () => {
      try {
         const res = await fetch(`${API_URL}/history`);
         const data = await res.json();
         setHistory(data);
      } catch (e) { console.error(e); }
   };

   const testOllamaConnection = async () => {
      if (!ollamaUrl.trim()) {
         setOllamaTestResult({ ok: false, message: "Veuillez entrer une URL" });
         return;
      }

      setOllamaTesting(true);
      setOllamaTestResult(null);

      try {
         const res = await fetch(`${API_URL}/ollama/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: ollamaUrl })
         });
         const data = await res.json();
         setOllamaTestResult(data);
      } catch (e) {
         setOllamaTestResult({ ok: false, message: "Backend hors ligne" });
      } finally {
         setOllamaTesting(false);
      }
   };

   // Scroll only the log container, never the page
   const scrollToBottom = () => {
      if (logFollowRef.current && logContainerRef.current) {
         logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
      }
   };

   // Called by the log container's onScroll — sets follow mode
   const handleLogScroll = () => {
      const el = logContainerRef.current;
      if (!el) return;
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
      logFollowRef.current = atBottom;
      setShowScrollBack(!atBottom);
   };

   // "Back to bottom" button handler
   const jumpToBottom = () => {
      logFollowRef.current = true;
      setShowScrollBack(false);
      if (logContainerRef.current) {
         logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
      }
   };

   const goToPreflight = async () => {
      // Clear previous errors
      setTargetError('');
      setOllamaUrlError('');

      // Validation
      if (!target || target.trim() === '') {
         setTargetError('Veuillez entrer une cible (URL Git ou chemin local)');
         toast.error('Veuillez entrer une cible valide');
         return;
      }

      if (ollamaMode === 'remote' && !ollamaUrl.trim()) {
         setOllamaUrlError('URL Ollama requise en mode distant');
         toast.error('Veuillez renseigner l\'URL Ollama');
         return;
      }

      setPreflightLoading(true);
      setPreflightError(null);
      setPreflightData(null);

      try {
         const params = new URLSearchParams({
            target,
            profile,
            mode: scanMode,
            ollama_mode: ollamaMode,
         });
         if (ollamaMode === 'remote' && ollamaUrl.trim()) {
            params.set('ollama_url', ollamaUrl.trim());
         }
         const res = await fetch(`${API_URL}/scan/preflight?${params.toString()}`, {
            signal: AbortSignal.timeout(60000)
         });
         const data = await res.json();
         if (!data.success) {
            throw new Error(data.message || 'Preflight failed');
         }
         setPreflightData(data.preflight);
         setView('preflight');
      } catch (e) {
         const msg = e.message || 'Backend hors ligne';
         setPreflightError(msg);
         toast.error(`Preflight échoué: ${msg}`);
      } finally {
         setPreflightLoading(false);
      }
   };

   const retryPreflight = () => goToPreflight();

   const startScan = async () => {
      try {
         await fetch(`${API_URL}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
               target,
               profile,
               mode: scanMode,
               ollama_mode: ollamaMode,
               ollama_url: ollamaMode === 'remote' ? ollamaUrl : null
            })
         });
         setStatus(prev => ({ ...prev, is_scanning: true, progress: 1 }));
         setView('running');
         setActiveTab('logs');
         toast.success('Scan lancé avec succès');
      } catch (e) {
         toast.error('Backend hors ligne - vérifiez que le serveur est démarré');
      }
   };

   const stopScan = async () => {
      try {
         // 1. Appeler l'API stop
         await fetch(`${API_URL}/scan/stop`, { method: 'POST' });

         // 2. Arrêter le polling immédiatement en forçant is_scanning=false localement
         setStatus(prev => ({
            ...prev,
            is_scanning: false,
            should_stop: true
         }));

         // 3. Feedback visuel
         console.log('🛑 Stop demandé - polling arrêté');
      } catch (e) {
         console.error('Erreur stop:', e);
      }
   };

   const downloadReport = () => window.open(`${API_URL}/export/report`, '_blank');
   const downloadJSON = () => window.open(`${API_URL}/export/json`, '_blank');

   const generateFix = async (vulnId) => {
      setAutoFixLoading(vulnId);
      setAutoFixError(null);
      setAutoFixSuccess(null);
      try {
         const res = await fetch(`${API_URL}/fix/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vuln_id: vulnId })
         });
         const data = await res.json();

         if (data.success) {
            setAutoFixSuccess(data.patch_file);
            toast.success(`Patch généré: ${data.patch_file}`, 8000);
         } else {
            const errMsg = data.error || 'Échec génération patch';
            setAutoFixError(errMsg);
            toast.error(`Échec: ${errMsg}`);
         }
      } catch (e) {
         const errMsg = 'Backend hors ligne ou erreur réseau';
         setAutoFixError(errMsg);
         toast.error(errMsg);
      } finally {
         setAutoFixLoading(null);
      }
   };

   const filterVulnerabilities = () => {
      let filtered = status.vulnerabilities || [];

      if (searchQuery) {
         const query = searchQuery.toLowerCase();
         filtered = filtered.filter(v =>
            v.title?.toLowerCase().includes(query) ||
            v.description?.toLowerCase().includes(query) ||
            v.file?.toLowerCase().includes(query) ||
            v.snippet?.toLowerCase().includes(query) ||
            v.type?.toLowerCase().includes(query) ||
            (v.line && v.line.toString().includes(query))
         );
      }

      if (selectedSeverities.length > 0) {
         filtered = filtered.filter(v => selectedSeverities.includes(v.severity));
      }

      if (selectedFiles.length > 0) {
         filtered = filtered.filter(v => selectedFiles.includes(v.file));
      }

      return filtered;
   };

   const toggleSeverity = (sev) => {
      setSelectedSeverities(prev =>
         prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
      );
   };

   const toggleFile = (file) => {
      setSelectedFiles(prev =>
         prev.includes(file) ? prev.filter(f => f !== file) : [...prev, file]
      );
   };

   const toggleCardExpand = (id) => {
      setExpandedCards(prev => {
         const newSet = new Set(prev);
         if (newSet.has(id)) {
            newSet.delete(id);
         } else {
            newSet.add(id);
         }
         return newSet;
      });
   };

   // Guided Analysis
   const getTopVulnerabilities = () => {
      const vulns = status.vulnerabilities || [];
      const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
      return [...vulns]
         .sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0))
         .slice(0, 5);
   };

   const getEstimatedFixTime = (severity) => {
      const times = { Critical: "2-4h", High: "1-2h", Medium: "30min-1h", Low: "15-30min" };
      return times[severity] || "N/A";
   };

   const getBusinessImpact = (severity, type) => {
      if (severity === 'Critical') {
         if (type?.toLowerCase().includes('rce')) return "🔴 Production compromise possible";
         if (type?.toLowerCase().includes('sql')) return "🔴 Data breach imminent";
         return "🔴 Système à risque élevé";
      }
      if (severity === 'High') return "🟠 Sécurité compromise";
      if (severity === 'Medium') return "🟡 Risque modéré";
      return "🟢 Amélioration recommandée";
   };

   const uniqueFiles = [...new Set((status.vulnerabilities || []).map(v => v.file))];
   const filteredVulns = filterVulnerabilities();

   const severityIcons = {
      'Critical': '🟥',
      'High': '🟧',
      'Medium': '🟨',
      'Low': '🟩'
   };

   // === RESULTS EXPLORER LOGIC  ===
   const selectedFinding = status.vulnerabilities.find(v => v.id === selectedVulnId);
   const dedupedVulns = deduplicateFindings(status.vulnerabilities);
   const filteredFindings = resultsFilter === 'ALL'
      ? dedupedVulns
      : dedupedVulns.filter(v => v.severity.toUpperCase() === resultsFilter);

   // Apply search filter
   const searchedFindings = resultsSearch
      ? filteredFindings.filter(v =>
         v.title?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.file?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.description?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.type?.toLowerCase().includes(resultsSearch.toLowerCase())
      )
      : filteredFindings;

   // Group by file if needed
   const groupedByFile = React.useMemo(() => {
      const groups = {};
      for (const f of searchedFindings) {
         const file = f.file || f.filepath || 'Unknown';
         if (!groups[file]) groups[file] = [];
         groups[file].push(f);
      }
      // Sort files by highest severity first
      const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return Object.entries(groups).sort((a, b) => {
         const maxA = Math.max(...a[1].map(v => SEV_ORDER[normalizeSeverity(v.severity)] || 0));
         const maxB = Math.max(...b[1].map(v => SEV_ORDER[normalizeSeverity(v.severity)] || 0));
         return maxB - maxA;
      });
   // eslint-disable-next-line react-hooks/exhaustive-deps
   }, [searchedFindings]);

   const copyJSON = (obj) => {
      navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
      toast.success('JSON copié dans le presse-papier');
   };

   // Normalize severity for SEVERITY_STYLES mapping
   const normalizeSeverity = (sev) => {
      const normalized = sev?.toUpperCase();
      return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized) ? normalized : 'LOW';
   };

   // Deduplicate by rule+file+line (keep highest confidence)
   const deduplicateFindings = (vulns) => {
      const seen = new Map();
      for (const v of vulns) {
         const key = `${v.type || v.title}|${v.file || v.filepath}|${v.line || v.line_start || ''}`;
         const existing = seen.get(key);
         if (!existing || (v.confidence || 0) > (existing.confidence || 0)) {
            seen.set(key, v);
         }
      }
      return Array.from(seen.values());
   };

   // Remediation bucket: Urgent=Critical, Court=High, Moyen=Medium, Backlog=Low
   const remediationBuckets = React.useMemo(() => {
      const vulns = status.vulnerabilities;
      return {
         urgent:  vulns.filter(v => normalizeSeverity(v.severity) === 'CRITICAL'),
         court:   vulns.filter(v => normalizeSeverity(v.severity) === 'HIGH'),
         moyen:   vulns.filter(v => normalizeSeverity(v.severity) === 'MEDIUM'),
         backlog: vulns.filter(v => normalizeSeverity(v.severity) === 'LOW'),
      };
   // eslint-disable-next-line react-hooks/exhaustive-deps
   }, [status.vulnerabilities]);

   return (
      <div className={`min-h-screen transition-colors duration-300 ${theme === 'dark'
         ? 'bg-slate-950 text-slate-100'
         : 'bg-slate-50 text-slate-900'
         } font-sans selection:bg-indigo-500/30`}>

         {/* HEADER */}
         <header className={`border-b sticky top-0 z-20 backdrop-blur-md ${theme === 'dark'
            ? 'border-slate-800 bg-slate-900/80'
            : 'border-slate-200 bg-white/80'
            }`}>
            <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
               <div className="flex items-center gap-3">
                  <div className="bg-gradient-to-br from-indigo-600 to-violet-600 p-2 rounded-lg shadow-lg">
                     <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div>
                     <h1 className="text-xl font-bold tracking-tight leading-none">Nexus <span className="text-indigo-400">Auditor</span></h1>
                     <span className={`text-xs font-medium tracking-wider ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>ENTERPRISE EDITION V3.0</span>
                  </div>
               </div>

               <div className="flex items-center gap-4">
                  {/* Service Health Indicator */}
                  <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border ${serviceHealth.api === 'online'
                     ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                     : serviceHealth.api === 'offline'
                        ? 'bg-red-500/10 border-red-500/20 text-red-500'
                        : 'bg-slate-500/10 border-slate-500/20 text-slate-500'
                     }`}>
                     <div className={`w-2 h-2 rounded-full ${serviceHealth.api === 'online' ? 'bg-emerald-500 animate-pulse' :
                        serviceHealth.api === 'offline' ? 'bg-red-500' : 'bg-slate-500'
                        }`} />
                     <span>API {serviceHealth.api === 'online' ? 'Online' : serviceHealth.api === 'offline' ? 'Offline' : 'Unknown'}</span>
                  </div>

                  {/* History button */}
                  <button
                     onClick={() => { setShowHistory(true); loadHistory(); }}
                     className={`flex items-center gap-1.5 p-2 rounded-lg transition-all text-xs font-medium ${theme === 'dark'
                        ? 'bg-slate-800 hover:bg-slate-700 text-slate-400'
                        : 'bg-slate-200 hover:bg-slate-300 text-slate-600'
                        }`}
                     title="Historique des scans"
                  >
                     <History className="w-4 h-4" />
                     {history.length > 0 && <span>{history.length}</span>}
                  </button>

                  <button
                     onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                     className={`p-2 rounded-lg transition-all ${theme === 'dark'
                        ? 'bg-slate-800 hover:bg-slate-700 text-yellow-400'
                        : 'bg-slate-200 hover:bg-slate-300 text-indigo-600'
                        }`}
                     title={theme === 'dark' ? 'Mode clair' : 'Mode sombre'}
                  >
                     {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                  </button>

                  {view === 'results' && (
                     <>
                        <button onClick={downloadReport} className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm border transition-colors ${theme === 'dark'
                           ? 'bg-slate-800 hover:bg-slate-700 border-slate-700'
                           : 'bg-white hover:bg-slate-50 border-slate-300'
                           }`}>
                           <FileText className="w-4 h-4 text-indigo-400" /> Rapport HTML
                        </button>
                        <button onClick={downloadJSON} className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm border transition-colors ${theme === 'dark'
                           ? 'bg-slate-800 hover:bg-slate-700 border-slate-700'
                           : 'bg-white hover:bg-slate-50 border-slate-300'
                           }`}>
                           <Download className="w-4 h-4 text-emerald-400" /> JSON
                        </button>
                     </>
                  )}
               </div>
            </div>
         </header>

         <main className="max-w-7xl mx-auto px-6 py-8">
            {/* === CONFIG VIEW (Claude base) === */}
            {view === 'config' && (
               <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
                  <div className={`lg:col-span-2 rounded-2xl border p-6 shadow-xl relative overflow-hidden ${theme === 'dark'
                     ? 'bg-slate-900 border-slate-800'
                     : 'bg-white border-slate-200'
                     }`}>
                     <div className="absolute top-0 right-0 w-64 h-64 bg-indigo-500/5 rounded-full blur-3xl -z-10"></div>

                     <div className="flex items-center gap-2 mb-6">
                        <Activity className="w-5 h-5 text-indigo-400" />
                        <h2 className="text-lg font-semibold">Paramètres de l'Audit</h2>
                     </div>

                     <div className="space-y-6">
                        <div>
                           <label className={`block text-xs font-semibold uppercase tracking-wider mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                              }`}>Cible (URL Git ou Chemin Local)</label>
                           <div className="relative group">
                              <Search className={`absolute left-4 top-3.5 w-5 h-5 transition-colors ${theme === 'dark'
                                 ? 'text-slate-500 group-focus-within:text-indigo-400'
                                 : 'text-slate-400 group-focus-within:text-indigo-500'
                                 }`} />
                              <input
                                 type="text"
                                 value={target}
                                 onChange={(e) => { setTarget(e.target.value); setTargetError(''); }}
                                 placeholder="https://github.com/company/repo.git"
                                 className={`w-full border rounded-xl py-3 pl-12 pr-4 focus:outline-none focus:ring-1 transition-all font-mono text-sm ${targetError
                                    ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                                    : theme === 'dark'
                                       ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500 focus:ring-indigo-500'
                                       : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400 focus:ring-indigo-400'
                                    }`}
                              />
                           </div>
                           {targetError && (
                              <p className="text-red-500 text-xs mt-1 flex items-center gap-1">
                                 <AlertTriangle className="w-3 h-3" /> {targetError}
                              </p>
                           )}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                           <div>
                              <label className={`block text-xs font-semibold uppercase tracking-wider mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                                 }`}>Puissance IA</label>
                              <div className="grid grid-cols-2 gap-2">
                                 {['eco', 'balanced', 'elite', 'titan'].map(p => {
                                    const isTitan = p === 'titan';
                                    return (
                                       <button
                                          key={p}
                                          onClick={() => setProfile(p)}
                                          className={`py-2 px-3 rounded-lg text-sm font-medium border transition-all ${profile === p
                                             ? isTitan
                                                ? 'bg-purple-600/10 border-purple-500 text-purple-400'
                                                : 'bg-indigo-600/10 border-indigo-500 text-indigo-400'
                                             : theme === 'dark'
                                                ? 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-600'
                                                : 'bg-slate-100 border-slate-300 text-slate-600 hover:border-slate-400'
                                             }`}
                                          title={isTitan ? '🔥 RTX 5090 - 128k context' : ''}
                                       >
                                          {isTitan && '🔥 '}{p.charAt(0).toUpperCase() + p.slice(1)}
                                       </button>
                                    );
                                 })}
                              </div>
                              {profile === 'titan' && (
                                 <div className="mt-2 text-xs text-purple-400 flex items-center gap-1">
                                    <Zap className="w-3 h-3" /> RTX 5090 - Analyse parallèle 8x | 128k tokens
                                 </div>
                              )}
                           </div>

                           <div>
                              <label className={`block text-xs font-semibold uppercase tracking-wider mb-3 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                                 }`}>Mode de Scan</label>

                              <div className="grid grid-cols-1 gap-2">
                                 {[
                                    { key: 'rapid', label: 'Scan Rapide', icon: Zap, desc: '⏱ 1-2 min • 🎯 Essentiel' },
                                    { key: 'deep', label: 'Scan Profond', icon: Search, desc: '⏱ Long • 🔍 Précis' },
                                    { key: 'devsecops', label: 'DevSecOps', icon: Shield, desc: '🚀 Production • 🔐 Conformité' }
                                 ].map(({ key, label, icon: Icon, desc }) => {
                                    const modeStyle = MODE_STYLES[key];
                                    return (
                                       <button
                                          key={key}
                                          onClick={() => setScanMode(key)}
                                          className={`relative p-3 rounded-lg border transition-all text-left ${scanMode === key
                                             ? modeStyle.active
                                             : theme === 'dark'
                                                ? 'border-slate-800 bg-slate-950 hover:border-slate-600'
                                                : 'border-slate-300 bg-slate-100 hover:border-slate-400'
                                             }`}
                                       >
                                          <div className="flex items-center gap-2 mb-1">
                                             <Icon className={`w-5 h-5 ${scanMode === key ? modeStyle.iconActive : modeStyle.iconInactive}`} />
                                             <h3 className="font-semibold text-sm">{label}</h3>
                                          </div>
                                          <div className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>{desc}</div>
                                       </button>
                                    );
                                 })}
                              </div>
                           </div>
                        </div>


                        {/* OLLAMA CONNECTION (V2.5) */}
                        <div className="mt-6">
                           <label className={`block text-xs font-semibold uppercase tracking-wider mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                              }`}>Connexion Ollama</label>

                           <div className="flex gap-2 mb-3">
                              <button
                                 onClick={() => { setOllamaMode('auto'); setOllamaTestResult(null); }}
                                 className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium border transition-all ${ollamaMode === 'auto'
                                    ? 'bg-indigo-600/10 border-indigo-500 text-indigo-400'
                                    : theme === 'dark'
                                       ? 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-600'
                                       : 'bg-slate-100 border-slate-300 text-slate-600 hover:border-slate-400'
                                    }`}
                              >
                                 🔄 Auto (recommandé)
                              </button>
                              <button
                                 onClick={() => { setOllamaMode('remote'); setOllamaTestResult(null); }}
                                 className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium border transition-all ${ollamaMode === 'remote'
                                    ? 'bg-indigo-600/10 border-indigo-500 text-indigo-400'
                                    : theme === 'dark'
                                       ? 'bg-slate-950 border-slate-800 text-slate-500 hover:border-slate-600'
                                       : 'bg-slate-100 border-slate-300 text-slate-600 hover:border-slate-400'
                                    }`}
                              >
                                 🌐 Serveur distant
                              </button>
                           </div>

                           {ollamaMode === 'remote' && (
                              <div className="space-y-2">
                                 <input
                                    type="text"
                                    value={ollamaUrl}
                                    onChange={(e) => { setOllamaUrl(e.target.value); setOllamaUrlError(''); setOllamaTestResult(null); }}
                                    placeholder="192.168.1.50:11434 ou http://..."
                                    className={`w-full border rounded-lg py-2 px-3 focus:outline-none focus:ring-1 transition-all font-mono text-sm ${ollamaUrlError
                                       ? 'border-red-500 focus:border-red-500 focus:ring-red-500'
                                       : theme === 'dark'
                                          ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500 focus:ring-indigo-500'
                                          : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400 focus:ring-indigo-400'
                                       }`}
                                 />
                                 {ollamaUrlError && (
                                    <p className="text-red-500 text-xs flex items-center gap-1">
                                       <AlertTriangle className="w-3 h-3" /> {ollamaUrlError}
                                    </p>
                                 )}
                                 <button
                                    onClick={testOllamaConnection}
                                    disabled={ollamaTesting || !ollamaUrl.trim()}
                                    className={`w-full py-2 px-3 rounded-lg text-sm font-medium border transition-all ${theme === 'dark'
                                       ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
                                       : 'bg-slate-100 hover:bg-slate-200 border-slate-300 text-slate-700'
                                       } disabled:opacity-50 disabled:cursor-not-allowed`}
                                 >
                                    {ollamaTesting ? '⏳ Test en cours...' : '🔍 Tester la connexion'}
                                 </button>

                                 {ollamaTestResult && (
                                    <div className={`p-3 rounded-lg border text-sm ${ollamaTestResult.ok
                                       ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                       : 'bg-red-500/10 border-red-500/20 text-red-400'
                                       }`}>
                                       <div className="font-semibold mb-1">{ollamaTestResult.ok ? '✅ ' : '❌ '}{ollamaTestResult.message}</div>
                                       {ollamaTestResult.models && ollamaTestResult.models.length > 0 && (
                                          <div className={`text-xs mt-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                                             Modèles: {ollamaTestResult.models.slice(0, 5).join(', ')}
                                             {ollamaTestResult.models.length > 5 && ` (+${ollamaTestResult.models.length - 5} autres)`}
                                          </div>
                                       )}
                                    </div>
                                 )}
                              </div>
                           )}

                           {ollamaMode === 'auto' && (
                              <div className={`text-xs p-2 rounded ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>
                                 Détection automatique (localhost:11434 ou Docker)
                              </div>
                           )}
                        </div>

                        {/* Pipeline Overview - What Nexus Will Do */}
                        <div className={`mt-6 p-4 rounded-xl border ${theme === 'dark'
                           ? 'bg-slate-800/50 border-slate-700'
                           : 'bg-slate-50 border-slate-200'
                           }`}>
                           <div className="flex items-center gap-2 mb-3">
                              <Layers className="w-4 h-4 text-indigo-400" />
                              <h3 className="text-sm font-semibold">Ce que Nexus va faire</h3>
                           </div>
                           <div className="grid grid-cols-5 gap-2">
                              {[
                                 { label: 'Normalize', icon: '📋', desc: 'Code parsing' },
                                 { label: 'Index', icon: '🔍', desc: 'File mapping' },
                                 { label: 'Analyze', icon: '🧠', desc: 'AI scanning' },
                                 { label: 'Correlate', icon: '🔗', desc: 'Pattern matching' },
                                 { label: 'Report', icon: '📊', desc: 'Results' }
                              ].map((stage, i) => (
                                 <div key={i} className="text-center">
                                    <div className={`text-lg mb-1 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{stage.icon}</div>
                                    <div className="text-xs font-medium mb-0.5">{stage.label}</div>
                                    <div className={`text-[10px] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>{stage.desc}</div>
                                 </div>
                              ))}
                           </div>
                        </div>

                        <div className={`pt-4 flex items-center justify-between border-t ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'
                           }`}>
                           <div className={`flex items-center gap-4 text-sm font-mono ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                              }`}>
                              <span className="flex items-center gap-1.5"><Clock className="w-4 h-4 text-indigo-400" /> {status.estimated_time}</span>
                           </div>

                           <button
                              onClick={goToPreflight}
                              disabled={preflightLoading}
                              className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed text-white px-8 py-2.5 rounded-xl font-medium shadow-lg shadow-indigo-600/20 transition-all flex items-center gap-2"
                           >
                              {preflightLoading ? (
                                 <>
                                    <Activity className="w-4 h-4 animate-spin" /> Analyse en cours...
                                 </>
                              ) : (
                                 <>
                                    <ChevronRight className="w-4 h-4" /> Continuer
                                 </>
                              )}
                           </button>
                        </div>

                        {/* Inline preflight error */}
                        {preflightError && (
                           <div className="mt-3 p-3 rounded-lg border border-red-500/30 bg-red-500/10 flex items-start gap-3">
                              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                              <div className="flex-1">
                                 <p className="text-sm text-red-400 font-medium">Preflight échoué</p>
                                 <p className={`text-xs mt-0.5 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{preflightError}</p>
                              </div>
                              <button
                                 onClick={retryPreflight}
                                 disabled={preflightLoading}
                                 className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 border border-red-500/30 px-2 py-1 rounded"
                              >
                                 <RotateCcw className="w-3 h-3" /> Réessayer
                              </button>
                           </div>
                        )}
                     </div>
                  </div>

                  {/* KPI CARDS */}
                  <div className="space-y-4">
                     <div className="grid grid-cols-2 gap-4">
                        <StatCard title="Critical" count={status.stats.critical} color="red" icon="🟥" theme={theme} />
                        <StatCard title="High" count={status.stats.high} color="orange" icon="🟧" theme={theme} />
                     </div>
                     <div className="grid grid-cols-2 gap-4">
                        <StatCard title="Medium" count={status.stats.medium} color="yellow" icon="🟨" theme={theme} />
                        <StatCard title="Files" count={status.stats.files} color="blue" icon="📁" theme={theme} />
                     </div>

                     <div className={`rounded-xl p-4 flex flex-col items-center justify-center py-6 border ${theme === 'dark'
                        ? 'bg-slate-900 border-slate-800'
                        : 'bg-white border-slate-200'
                        }`}>
                        <span className={`text-xs uppercase tracking-wider font-semibold mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'
                           }`}>Confiance Globale</span>
                        <div className="text-4xl font-bold text-emerald-400">
                           {status.confidence_score || 0}%
                        </div>
                     </div>
                  </div>
               </div>
            )}

            {/* === PREFLIGHT VIEW === */}
            {view === 'preflight' && preflightData && (
               <PreflightView
                  data={preflightData}
                  target={target}
                  profile={profile}
                  scanMode={scanMode}
                  theme={theme}
                  onBack={() => setView('config')}
                  onStart={startScan}
               />
            )}

            {/* === RUNNING VIEW === */}
            {view === 'running' && (
               <div className="space-y-3">

                  {/* ── STICKY ACTION BAR ── always visible, never scrolled away */}
                  <div className={`sticky top-16 z-20 rounded-xl border px-4 py-3 flex items-center gap-4 shadow-lg ${theme === 'dark' ? 'bg-slate-900/95 border-slate-800 backdrop-blur-md' : 'bg-white/95 border-slate-200 backdrop-blur-md'}`}>
                     {/* Progress + file */}
                     <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1.5">
                           <Activity className="w-4 h-4 text-indigo-500 animate-pulse shrink-0" />
                           <span className="text-sm font-semibold">Scan en cours…</span>
                           <span className="text-xl font-bold font-mono text-indigo-500 ml-auto shrink-0">{Math.round(status.progress)}%</span>
                        </div>
                        <div className={`h-1.5 rounded-full overflow-hidden ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>
                           <div
                              className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300 ease-out"
                              style={{ width: `${status.progress}%` }}
                           />
                        </div>
                        <p className={`font-mono text-xs mt-1 truncate ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>{status.current_file || `Estimé: ${status.estimated_time}`}</p>
                     </div>
                     {/* Severity live counters */}
                     <div className="flex items-center gap-2 shrink-0">
                        {[
                           { l: 'C', v: status.stats.critical,                                                           cls: 'text-red-400 border-red-500/30 bg-red-500/10' },
                           { l: 'H', v: status.stats.high,                                                               cls: 'text-orange-400 border-orange-500/30 bg-orange-500/10' },
                           { l: 'M', v: status.stats.medium,                                                             cls: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' },
                           { l: 'T', v: status.stats.critical + status.stats.high + status.stats.medium + status.stats.low, cls: 'text-slate-400 border-slate-500/30 bg-slate-500/10' },
                        ].map(({ l, v, cls }) => (
                           <div key={l} className={`flex flex-col items-center px-2 py-1 rounded border text-xs font-bold ${cls}`}>
                              <span className="text-base leading-none">{v}</span>
                              <span className="text-[9px] opacity-70">{l}</span>
                           </div>
                        ))}
                     </div>
                     {/* Stop button — always reachable */}
                     <button
                        onClick={stopScan}
                        className="shrink-0 flex items-center gap-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/40 px-4 py-2 rounded-lg font-medium transition-all text-sm"
                     >
                        <XCircle className="w-4 h-4" /> Arrêter
                     </button>
                  </div>

                  {/* Reconnecting banner */}
                  {pollingState === 'reconnecting' && (
                     <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 text-sm">
                        <Activity className="w-4 h-4 animate-spin shrink-0" />
                        Reconnexion au backend… Le dernier état affiché est conservé.
                     </div>
                  )}

                  {/* Stuck detector banner */}
                  {stuckWarning && (
                     <div className="flex items-start gap-3 px-4 py-3 rounded-lg border border-orange-500/40 bg-orange-500/10 text-orange-400 text-sm">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <div className="flex-1">
                           <p className="font-semibold">
                              Étape <span className="font-mono">{stuckWarning.stage}</span> bloquée depuis {stuckWarning.elapsed}s
                              (seuil {STUCK_THRESHOLDS[profile] || 180}s pour profil {profile})
                           </p>
                           <p className="text-xs mt-0.5 text-orange-300">Vérifiez qu'Ollama répond. Si le problème persiste, arrêtez et relancez.</p>
                        </div>
                        <div className="flex gap-2 shrink-0">
                           <button
                              onClick={() => fetch(`${API_URL}/scan/status`).then(r => r.json()).then(d => { setStatus(d); toast.success('Status rafraîchi'); }).catch(() => toast.error('Impossible de rafraîchir'))}
                              className="flex items-center gap-1 text-xs border border-orange-500/30 px-2 py-1 rounded hover:bg-orange-500/10"
                           >
                              <RotateCcw className="w-3 h-3" /> Retry
                           </button>
                           <button
                              onClick={() => { navigator.clipboard.writeText(status.logs.map(l => `[${l.time}] ${l.msg}`).join('\n')); toast.success('Logs copiés'); }}
                              className="flex items-center gap-1 text-xs border border-orange-500/30 px-2 py-1 rounded hover:bg-orange-500/10"
                           >
                              <Copy className="w-3 h-3" /> Logs
                           </button>
                        </div>
                     </div>
                  )}

                  {/* Progress bar card removed — merged into sticky bar above */}

                  {/* Pipeline Stages Timeline */}
                  <div className={`rounded-xl border p-4 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                     <div className="flex items-center gap-2 mb-3">
                        <Layers className="w-4 h-4 text-indigo-400" />
                        <h3 className="text-sm font-semibold">Pipeline</h3>
                     </div>
                     <div className="flex items-stretch gap-1">
                        {PIPELINE_STAGES.map((s, i) => {
                           const isActive = lastStage === s.key || (!lastStage && i === 0 && status.progress > 0);
                           const heuristicStage = Math.ceil((status.progress / 100) * PIPELINE_STAGES.length);
                           const isDone = heuristicStage > s.idx;
                           const isStuck = stuckWarning?.stage === s.key;
                           const elapsed = stageTimers[s.key] ? Math.round((Date.now() - stageTimers[s.key]) / 1000) : null;

                           return (
                              <React.Fragment key={s.key}>
                                 <div className={`flex-1 text-center p-2 rounded-lg border transition-all ${isStuck
                                    ? 'bg-orange-500/10 border-orange-500/40 text-orange-400'
                                    : isDone
                                       ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500'
                                       : isActive
                                          ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400 animate-pulse'
                                          : theme === 'dark' ? 'bg-slate-800 border-slate-700 text-slate-500' : 'bg-slate-100 border-slate-300 text-slate-400'
                                    }`}>
                                    <div className="text-base mb-0.5">{s.icon}</div>
                                    <div className="text-[11px] font-medium">{s.label}</div>
                                    {isDone && <div className="text-[9px] mt-0.5 text-emerald-400">✓</div>}
                                    {isActive && !isDone && elapsed !== null && (
                                       <div className="text-[9px] mt-0.5 font-mono">{elapsed}s</div>
                                    )}
                                    {isStuck && <div className="text-[9px] mt-0.5">⚠</div>}
                                 </div>
                                 {i < PIPELINE_STAGES.length - 1 && (
                                    <div className={`w-3 flex items-center`}>
                                       <div className={`w-full h-0.5 ${isDone ? 'bg-emerald-500' : theme === 'dark' ? 'bg-slate-700' : 'bg-slate-300'}`} />
                                    </div>
                                 )}
                              </React.Fragment>
                           );
                        })}
                     </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                     {/* Terminal */}
                     <div className="lg:col-span-2">
                        <div className="relative bg-slate-950 rounded-xl border border-slate-800 h-[420px] flex flex-col font-mono text-xs overflow-hidden shadow-2xl">
                           <div className="px-3 py-2 border-b border-slate-800 bg-slate-900/50 flex items-center gap-2 flex-wrap">
                              <div className="flex items-center gap-1.5 text-slate-400 shrink-0">
                                 <Terminal size={13} />
                                 <span>Console</span>
                              </div>
                              {/* Log level filters with counts */}
                              <div className="flex items-center gap-1 bg-slate-900 rounded px-1">
                                 {LOG_FILTER_LEVELS.map(f => {
                                    const count = f.key === 'all' ? status.logs.length : status.logs.filter(l => classifyLog(l) === f.key).length;
                                    return (
                                       <button
                                          key={f.key}
                                          onClick={() => setLogFilter(f.key)}
                                          className={`px-2 py-0.5 text-[10px] rounded transition-all flex items-center gap-1 ${logFilter === f.key ? f.activeClass : 'text-slate-500 hover:text-slate-300'}`}
                                       >
                                          {f.label}
                                          {count > 0 && <span className={`text-[9px] px-1 rounded ${logFilter === f.key ? 'bg-white/20' : 'bg-slate-800'}`}>{count}</span>}
                                       </button>
                                    );
                                 })}
                              </div>
                              {/* Search */}
                              <div className="relative flex-1 min-w-[100px]">
                                 <Search className="absolute left-2 top-1 w-3 h-3 text-slate-500" />
                                 <input
                                    type="text"
                                    value={logSearch}
                                    onChange={e => setLogSearch(e.target.value)}
                                    placeholder="Filtrer…"
                                    className="w-full bg-slate-900 border border-slate-800 rounded pl-6 pr-2 py-0.5 text-[10px] text-slate-300 focus:outline-none focus:border-indigo-500"
                                 />
                              </div>
                              {/* Copy all logs */}
                              <button
                                 onClick={() => { navigator.clipboard.writeText(status.logs.map(l => `[${l.time}] ${l.msg}`).join('\n')); toast.success('Logs copiés'); }}
                                 className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                                 title="Copier tous les logs"
                              >
                                 <Copy size={12} />
                              </button>
                              {/* Download */}
                              <button
                                 onClick={() => {
                                    const logText = status.logs.map(l => `[${l.time}] ${l.msg}`).join('\n');
                                    const blob = new Blob([logText], { type: 'text/plain' });
                                    const url = URL.createObjectURL(blob);
                                    const a = document.createElement('a');
                                    a.href = url; a.download = `nexus-logs-${Date.now()}.txt`; a.click();
                                    URL.revokeObjectURL(url);
                                    toast.success('Logs téléchargés');
                                 }}
                                 className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                                 title="Télécharger logs"
                              >
                                 <Download size={12} />
                              </button>
                           </div>
                           {/* Scrollable log body — scrolls the container, never the page */}
                           <div
                              ref={logContainerRef}
                              onScroll={handleLogScroll}
                              className="flex-1 p-3 overflow-y-auto space-y-0.5 custom-scrollbar relative"
                           >
                              {status.logs.filter(log => {
                                 const cls = classifyLog(log);
                                 if (logFilter !== 'all' && cls !== logFilter) return false;
                                 if (logSearch && !log.msg.toLowerCase().includes(logSearch.toLowerCase())) return false;
                                 return true;
                              }).map((log, i) => {
                                 const cls = classifyLog(log);
                                 const colorClass = LOG_COLOR_CLASSES[cls] || 'text-slate-300';
                                 return (
                                    <div
                                       key={i}
                                       className="flex gap-3 hover:bg-slate-900/50 p-0.5 rounded group cursor-pointer"
                                       onClick={() => { navigator.clipboard.writeText(`[${log.time}] ${log.msg}`); toast.success('Log copié'); }}
                                       title="Click to copy"
                                    >
                                       <span className="text-slate-600 shrink-0 tabular-nums">[{log.time}]</span>
                                       <span className={colorClass}>{log.msg}</span>
                                       <Copy className="w-3 h-3 text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity ml-auto shrink-0" />
                                    </div>
                                 );
                              })}
                              <div ref={logEndRef} />
                           </div>
                           {/* "Back to bottom" button — shown when user scrolled up */}
                           {showScrollBack && (
                              <button
                                 onClick={jumpToBottom}
                                 className="absolute bottom-3 right-4 flex items-center gap-1.5 text-[11px] bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-full shadow-lg transition-all"
                              >
                                 <ChevronDown className="w-3 h-3" /> Revenir en bas
                              </button>
                           )}
                        </div>
                     </div>

                     {/* Live Stats — detailed breakdown (Stop is in sticky bar) */}
                     <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                           {[
                              { label: 'CRITICAL', val: status.stats.critical, cls: SEVERITY_STYLES.CRITICAL.badge },
                              { label: 'HIGH', val: status.stats.high, cls: SEVERITY_STYLES.HIGH.badge },
                              { label: 'MEDIUM', val: status.stats.medium, cls: SEVERITY_STYLES.MEDIUM.badge },
                              { label: 'TOTAL', val: status.stats.critical + status.stats.high + status.stats.medium + status.stats.low, cls: 'bg-slate-500/10 text-slate-400 border-slate-500/20' },
                           ].map(({ label, val, cls }) => (
                              <div key={label} className={`p-3 rounded-xl border ${cls} flex flex-col items-center justify-center`}>
                                 <span className="text-2xl font-bold">{val}</span>
                                 <span className="text-[10px] font-bold uppercase tracking-widest opacity-80">{label}</span>
                              </div>
                           ))}
                        </div>
                        {/* Secondary Stop button for sidebar — same action, redundant for UX clarity */}
                        <button onClick={stopScan} className="w-full bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 px-4 py-2 rounded-xl font-medium transition-all flex items-center justify-center gap-2 text-sm">
                           <XCircle className="w-4 h-4" /> Arrêter le Scan
                        </button>
                     </div>
                  </div>
               </div>
            )}

            {/* === RESULTS EXPLORER === */}
            {view === 'results' && (
               <div className="h-[calc(100vh-150px)] flex flex-col">
                  <div className="flex items-center justify-between mb-6 px-1">
                     <div>
                        <h2 className="text-2xl font-bold flex items-center gap-3">
                           Rapport d'Audit
                           <span className="text-sm font-normal px-3 py-1 bg-emerald-500/10 text-emerald-500 rounded-full border border-emerald-500/20">
                              Scan complété
                           </span>
                        </h2>
                        <p className={`text-sm mt-1 ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>
                           {status.vulnerabilities.length} vulnérabilités détectées sur la cible.
                        </p>
                     </div>
                     <div className="flex items-center gap-3">
                        {/* Executive/Technical Toggle */}
                        <div className={`flex items-center gap-1 p-1 rounded-lg border ${theme === 'dark'
                           ? 'bg-slate-900 border-slate-700'
                           : 'bg-slate-100 border-slate-300'
                           }`}>
                           <button
                              onClick={() => setResultsViewMode('executive')}
                              className={`px-3 py-1.5 text-xs font-medium rounded transition-all ${resultsViewMode === 'executive'
                                 ? 'bg-indigo-600 text-white shadow-sm'
                                 : theme === 'dark' ? 'text-slate-400 hover:text-slate-300' : 'text-slate-600 hover:text-slate-700'
                                 }`}
                           >
                              <TrendingUp className="w-3 h-3 inline mr-1" />
                              Executive
                           </button>
                           <button
                              onClick={() => setResultsViewMode('technical')}
                              className={`px-3 py-1.5 text-xs font-medium rounded transition-all ${resultsViewMode === 'technical'
                                 ? 'bg-indigo-600 text-white shadow-sm'
                                 : theme === 'dark' ? 'text-slate-400 hover:text-slate-300' : 'text-slate-600 hover:text-slate-700'
                                 }`}
                           >
                              <Code className="w-3 h-3 inline mr-1" />
                              Technical
                           </button>
                        </div>

                        <button
                           onClick={() => setShowLogs(true)}
                           className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm border transition-colors ${theme === 'dark'
                              ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
                              : 'bg-white hover:bg-slate-50 border-slate-300 text-slate-700'
                              }`}
                        >
                           <Terminal size={16} /> Logs
                        </button>
                        <button
                           onClick={() => {
                              setView('config');
                              setSelectedVulnId(null);
                           }}
                           className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm border transition-colors ${theme === 'dark'
                              ? 'bg-slate-800 hover:bg-slate-700 border-slate-700'
                              : 'bg-white hover:bg-slate-50 border-slate-300'
                              }`}
                        >
                           <Shield size={16} /> Nouveau Scan
                        </button>
                     </div>
                  </div>

                  {status.vulnerabilities.length === 0 ? (
                     <div className={`flex flex-col items-center justify-center h-full border border-dashed rounded-xl ${theme === 'dark' ? 'border-slate-800' : 'border-slate-300'}`}>
                        <CheckCircle className={`w-16 h-16 mb-4 ${theme === 'dark' ? 'text-slate-700' : 'text-slate-300'}`} />
                        <p className={`text-lg font-semibold mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                           ✅ Aucune vulnérabilité critique détectée selon le niveau d'analyse sélectionné
                        </p>
                        {(scanMode === 'rapid' || scanMode === 'deep') && (
                           <p className={`text-sm ${theme === 'dark' ? 'text-slate-600' : 'text-slate-500'}`}>
                              💡 Essayez le mode <strong>DevSecOps</strong> pour une analyse exhaustive (toutes sévérités, tous fichiers)
                           </p>
                        )}
                     </div>
                  ) : (
                     resultsViewMode === 'executive' ? (
                        <ExecutiveView
                           vulnerabilities={status.vulnerabilities}
                           stats={status.stats}
                           theme={theme}
                        />
                     ) : (
                        <div className="space-y-4 flex-1 flex flex-col min-h-0">
                           {/* Remediation Plan strip */}
                           <div className={`rounded-xl border p-3 shrink-0 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                              <div className="flex items-center gap-2 mb-2">
                                 <Wrench className="w-3.5 h-3.5 text-indigo-400" />
                                 <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Plan de remédiation</span>
                                 {dedupedVulns.length < status.vulnerabilities.length && (
                                    <span className={`ml-auto text-[10px] px-2 py-0.5 rounded ${theme === 'dark' ? 'bg-slate-800 text-slate-500' : 'bg-slate-100 text-slate-500'}`}>
                                       {status.vulnerabilities.length - dedupedVulns.length} doublons masqués
                                    </span>
                                 )}
                              </div>
                              <div className="grid grid-cols-4 gap-2">
                                 {[
                                    { key: 'urgent',  label: 'Urgent',  sub: 'Patch immédiat', cls: 'border-red-500/30 bg-red-500/5 text-red-400',    count: remediationBuckets.urgent.length },
                                    { key: 'court',   label: 'Court',   sub: 'Sprint suivant',  cls: 'border-orange-500/30 bg-orange-500/5 text-orange-400', count: remediationBuckets.court.length },
                                    { key: 'moyen',   label: 'Moyen',   sub: 'Backlog priorité', cls: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-400', count: remediationBuckets.moyen.length },
                                    { key: 'backlog', label: 'Backlog', sub: 'Nice to fix',      cls: 'border-blue-500/30 bg-blue-500/5 text-blue-400',   count: remediationBuckets.backlog.length },
                                 ].map(({ label, sub, cls, count }) => (
                                    <div key={label} className={`rounded-lg border px-3 py-2 ${cls}`}>
                                       <div className="text-base font-bold">{count}</div>
                                       <div className="text-[11px] font-semibold">{label}</div>
                                       <div className="text-[10px] opacity-70">{sub}</div>
                                    </div>
                                 ))}
                              </div>
                           </div>

                           {/* List + Detail */}
                           <div className="flex-1 grid grid-cols-12 gap-4 min-h-0">
                              {/* LIST */}
                              <div className={`col-span-4 flex flex-col overflow-hidden rounded-xl border ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                                 {/* Filters row */}
                                 <div className={`px-3 pt-3 pb-2 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                                    <div className="flex gap-1.5 flex-wrap mb-2">
                                       <button
                                          onClick={() => setResultsFilter('ALL')}
                                          className={`px-2.5 py-1 rounded text-xs font-bold transition-colors ${resultsFilter === 'ALL' ? 'bg-slate-700 text-white' : 'text-slate-500 hover:bg-slate-800'}`}
                                       >
                                          ALL ({dedupedVulns.length})
                                       </button>
                                       {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                                          const cnt = dedupedVulns.filter(v => normalizeSeverity(v.severity) === sev).length;
                                          return (
                                             <button
                                                key={sev}
                                                onClick={() => setResultsFilter(sev)}
                                                className={`px-2.5 py-1 rounded text-xs font-bold transition-colors ${resultsFilter === sev ? SEVERITY_STYLES[sev].badge : 'text-slate-500 hover:bg-slate-800'}`}
                                             >
                                                {sev.slice(0, 4)} {cnt > 0 && `(${cnt})`}
                                             </button>
                                          );
                                       })}
                                    </div>
                                    {/* Search + group toggle */}
                                    <div className="flex items-center gap-2">
                                       <div className="relative flex-1">
                                          <Search className="absolute left-2.5 top-2 w-3.5 h-3.5 text-slate-400" />
                                          <input
                                             type="text"
                                             value={resultsSearch}
                                             onChange={(e) => setResultsSearch(e.target.value)}
                                             placeholder="Rechercher…"
                                             className={`w-full pl-7 pr-2 py-1.5 text-xs rounded-lg border ${theme === 'dark'
                                                ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500'
                                                : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400'
                                                } focus:outline-none`}
                                          />
                                       </div>
                                       <button
                                          onClick={() => setResultsGroupBy(g => g === 'flat' ? 'file' : 'flat')}
                                          className={`shrink-0 text-[10px] px-2 py-1.5 rounded border transition-colors ${resultsGroupBy === 'file'
                                             ? theme === 'dark' ? 'bg-indigo-600/20 border-indigo-500/50 text-indigo-400' : 'bg-indigo-100 border-indigo-300 text-indigo-600'
                                             : theme === 'dark' ? 'bg-slate-800 border-slate-700 text-slate-400' : 'bg-white border-slate-300 text-slate-600'
                                          }`}
                                          title="Grouper par fichier"
                                       >
                                          {resultsGroupBy === 'file' ? '📁 Fichier' : '≡ Plat'}
                                       </button>
                                    </div>
                                 </div>

                                 <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar">
                                    {searchedFindings.length === 0 && (
                                       <div className="text-center p-8 text-slate-500 text-sm">Aucun résultat.</div>
                                    )}
                                    {resultsGroupBy === 'flat'
                                       ? searchedFindings.map(f => (
                                          <FindingListItem
                                             key={f.id}
                                             finding={f}
                                             selected={selectedVulnId === f.id}
                                             onSelect={() => { setSelectedVulnId(f.id); setAutoFixError(null); setAutoFixSuccess(null); }}
                                             theme={theme}
                                          />
                                       ))
                                       : groupedByFile.map(([file, findings]) => (
                                          <div key={file} className="mb-2">
                                             <div className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold sticky top-0 z-10 ${theme === 'dark' ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'}`}>
                                                <FileText size={11} />
                                                <span className="truncate flex-1" title={file}>{file.split('/').pop()}</span>
                                                <span className={`shrink-0 px-1.5 rounded text-[10px] ${theme === 'dark' ? 'bg-slate-700 text-slate-500' : 'bg-slate-200 text-slate-500'}`}>{findings.length}</span>
                                             </div>
                                             {findings.map(f => (
                                                <FindingListItem
                                                   key={f.id}
                                                   finding={f}
                                                   selected={selectedVulnId === f.id}
                                                   onSelect={() => { setSelectedVulnId(f.id); setAutoFixError(null); setAutoFixSuccess(null); }}
                                                   theme={theme}
                                                />
                                             ))}
                                          </div>
                                       ))
                                    }
                                 </div>
                              </div>

                              {/* DETAIL */}
                              <div className={`col-span-8 flex flex-col overflow-hidden rounded-xl ${theme === 'dark' ? 'bg-[#0B1120]' : 'bg-slate-50'}`}>
                                 {selectedFinding ? (
                                    <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
                                       <div className="flex items-start gap-4 mb-5">
                                          {React.createElement(SEVERITY_STYLES[normalizeSeverity(selectedFinding.severity)].icon, {
                                             size: 28,
                                             className: `p-2.5 rounded-xl border ${SEVERITY_STYLES[normalizeSeverity(selectedFinding.severity)].badge} bg-opacity-10`
                                          })}
                                          <div className="flex-1">
                                             <h2 className={`text-lg font-bold ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>{selectedFinding.title}</h2>
                                             <div className={`flex flex-wrap items-center gap-3 mt-1.5 text-xs font-mono ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>
                                                <span className="flex items-center gap-1 truncate max-w-xs"><FileText size={12} /> {selectedFinding.file || selectedFinding.filepath}</span>
                                                {(selectedFinding.line || selectedFinding.line_start) && (
                                                   <span>L{selectedFinding.line || selectedFinding.line_start}{selectedFinding.line_end ? `–${selectedFinding.line_end}` : ''}</span>
                                                )}
                                                {selectedFinding.confidence && (
                                                   <span className={selectedFinding.confidence >= 70 ? 'text-emerald-400' : selectedFinding.confidence >= 40 ? 'text-yellow-400' : 'text-red-400'}>
                                                      {selectedFinding.confidence}% confiance
                                                   </span>
                                                )}
                                             </div>
                                          </div>
                                          <button
                                             onClick={() => copyJSON(selectedFinding)}
                                             className={`p-2 rounded-lg border transition-colors ${theme === 'dark'
                                                ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-400'
                                                : 'bg-white hover:bg-slate-50 border-slate-300 text-slate-600'
                                                }`}
                                             title="Copier JSON"
                                          >
                                             <Copy size={14} />
                                          </button>
                                       </div>

                                       <div className="space-y-6">
                                          {(selectedFinding.note || selectedFinding.needs_manual_review) && (
                                             <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 flex items-start gap-3">
                                                <AlertTriangle className="text-yellow-500 shrink-0 mt-0.5" size={16} />
                                                <div>
                                                   <h3 className="text-yellow-500 font-bold text-sm mb-1">Attention requise</h3>
                                                   <p className={`text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
                                                      {selectedFinding.note || "Examen manuel requis (preuve manquante)"}
                                                   </p>
                                                </div>
                                             </div>
                                          )}

                                          <div>
                                             <h3 className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-2">Analyse technique</h3>
                                             <p className={`text-sm leading-relaxed p-4 rounded-lg border ${theme === 'dark'
                                                ? 'bg-slate-900 border-slate-800 text-slate-300'
                                                : 'bg-white border-slate-200 text-slate-700'
                                                }`}>
                                                {selectedFinding.description}
                                                {(selectedFinding.impact && selectedFinding.impact !== "Non évalué") && (
                                                   <span className="block mt-3 pt-3 border-t border-slate-700 text-xs">
                                                      <strong>Impact:</strong> {selectedFinding.impact}
                                                   </span>
                                                )}
                                             </p>
                                          </div>

                                          {selectedFinding.snippet && selectedFinding.snippet !== "Code non disponible" && (
                                             <div>
                                                <h3 className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-2">Evidence</h3>
                                                <div className="bg-[#1e1e1e] rounded-lg border border-slate-800 overflow-hidden font-mono text-sm shadow-inner">
                                                   <div className="flex items-center justify-between px-4 py-2 bg-[#252526] border-b border-slate-800 text-xs text-slate-400">
                                                      <span className="truncate">{selectedFinding.file || selectedFinding.filepath}</span>
                                                      <span>RO</span>
                                                   </div>
                                                   <pre className="p-4 overflow-x-auto text-slate-300 text-xs">
                                                      <code>{selectedFinding.snippet}</code>
                                                   </pre>
                                                </div>
                                             </div>
                                          )}

                                          {selectedFinding.fix && (
                                             <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
                                                <h3 className="text-emerald-500 font-bold flex items-center gap-2 mb-2 text-sm">
                                                   <Wrench size={15} /> Recommandation
                                                </h3>
                                                <p className={`text-sm mb-3 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
                                                   {selectedFinding.fix}
                                                </p>
                                                {/* Fix workflow */}
                                                {autoFixSuccess ? (
                                                   <div className="flex items-center gap-3">
                                                      <span className="flex items-center gap-1.5 text-emerald-400 text-sm font-medium">
                                                         <CheckCircle size={14} /> Patch généré: <span className="font-mono text-xs">{autoFixSuccess}</span>
                                                      </span>
                                                      <button
                                                         onClick={() => window.open(`${API_URL}/fix/download/${autoFixSuccess}`, '_blank')}
                                                         className="flex items-center gap-1 text-xs text-emerald-400 border border-emerald-500/30 px-2.5 py-1.5 rounded hover:bg-emerald-500/10"
                                                      >
                                                         <Download size={11} /> Télécharger
                                                      </button>
                                                      <button
                                                         onClick={() => setAutoFixSuccess(null)}
                                                         className="text-xs text-slate-500 hover:text-slate-300"
                                                      >
                                                         ✕
                                                      </button>
                                                   </div>
                                                ) : autoFixError ? (
                                                   <div className="flex items-center gap-3">
                                                      <span className="flex items-center gap-1.5 text-red-400 text-xs">
                                                         <XCircle size={13} /> {autoFixError}
                                                      </span>
                                                      <button
                                                         onClick={() => generateFix(selectedFinding.id)}
                                                         className="text-xs text-red-400 border border-red-500/30 px-2.5 py-1.5 rounded hover:bg-red-500/10"
                                                      >
                                                         Réessayer
                                                      </button>
                                                   </div>
                                                ) : (
                                                   <button
                                                      onClick={() => generateFix(selectedFinding.id)}
                                                      disabled={autoFixLoading === selectedFinding.id || !((selectedFinding.file || selectedFinding.filepath) && (selectedFinding.line || selectedFinding.line_start) && selectedFinding.fix && selectedFinding.fix !== "Pas de correctif proposé.")}
                                                      className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs py-1.5 px-4 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
                                                   >
                                                      {autoFixLoading === selectedFinding.id ? (
                                                         <><Activity size={12} className="animate-spin" /> Génération…</>
                                                      ) : (
                                                         <><Wrench size={12} /> Générer correctif</>
                                                      )}
                                                   </button>
                                                )}
                                             </div>
                                          )}
                                       </div>
                                    </div>
                                 ) : (
                                    <div className="flex flex-col items-center justify-center h-full text-slate-400">
                                       <div className={`w-16 h-16 rounded-full flex items-center justify-center mb-4 ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-100'}`}>
                                          <Search size={24} />
                                       </div>
                                       <p>Sélectionnez une vulnérabilité pour voir les détails.</p>
                                    </div>
                                 )}
                              </div>
                           </div>
                        </div>
                     )
                  )}
               </div>
            )}

            {/* === HISTORY MODAL === */}
            {showHistory && (
               <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-6">
                  <div className={`w-full max-w-3xl max-h-[85vh] flex flex-col rounded-2xl shadow-2xl overflow-hidden border ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                     {/* Header */}
                     <div className={`flex items-center justify-between px-6 py-4 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                        <div className="flex items-center gap-3">
                           <History className="w-5 h-5 text-indigo-400" />
                           <div>
                              <h3 className="font-bold text-sm">Historique des scans</h3>
                              <p className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>{history.length} entrée{history.length !== 1 ? 's' : ''}</p>
                           </div>
                        </div>
                        <button onClick={() => setShowHistory(false)} className={`p-2 rounded-lg transition-colors ${theme === 'dark' ? 'hover:bg-slate-800 text-slate-400' : 'hover:bg-slate-100 text-slate-600'}`}>
                           <XCircle size={18} />
                        </button>
                     </div>

                     {/* Search */}
                     <div className={`px-4 py-3 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                        <div className="relative">
                           <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                           <input
                              type="text"
                              value={historySearch}
                              onChange={e => setHistorySearch(e.target.value)}
                              placeholder="Rechercher par cible, profil ou mode…"
                              className={`w-full pl-9 pr-3 py-2 text-sm rounded-lg border ${theme === 'dark'
                                 ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500'
                                 : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400'
                                 } focus:outline-none`}
                           />
                        </div>
                     </div>

                     {/* List */}
                     <div className="flex-1 overflow-y-auto p-4 space-y-2 custom-scrollbar">
                        {history.length === 0 && (
                           <p className={`text-center py-10 text-sm ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>Aucun scan dans l'historique.</p>
                        )}
                        {history.filter(h => {
                           if (!historySearch) return true;
                           const q = historySearch.toLowerCase();
                           return (h.target || '').toLowerCase().includes(q)
                              || (h.profile || '').toLowerCase().includes(q)
                              || (h.mode || '').toLowerCase().includes(q);
                        }).map((h, i) => {
                           const totalVulns = h.stats ? (h.stats.critical + h.stats.high + h.stats.medium + h.stats.low) : '?';
                           const durationMin = h.duration_seconds ? `${Math.round(h.duration_seconds / 60)}m ${h.duration_seconds % 60}s` : '—';
                           const tags = [
                              h.profile && { label: (h.profile.charAt(0).toUpperCase() + h.profile.slice(1)), cls: theme === 'dark' ? 'bg-violet-900/40 text-violet-400' : 'bg-violet-100 text-violet-600' },
                              h.mode && { label: h.mode, cls: theme === 'dark' ? 'bg-indigo-900/40 text-indigo-400' : 'bg-indigo-100 text-indigo-600' },
                              h.llm_budget?.concurrency && { label: `×${h.llm_budget.concurrency}`, cls: theme === 'dark' ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600' },
                           ].filter(Boolean);

                           return (
                              <div key={i} className={`rounded-xl border p-4 transition-all ${theme === 'dark' ? 'bg-slate-800/50 border-slate-700 hover:border-slate-600' : 'bg-slate-50 border-slate-200 hover:border-slate-300'}`}>
                                 <div className="flex items-start gap-3">
                                    <div className="flex-1 min-w-0">
                                       <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                                          {tags.map((t, ti) => (
                                             <span key={ti} className={`text-[10px] px-2 py-0.5 rounded font-semibold uppercase ${t.cls}`}>{t.label}</span>
                                          ))}
                                          {h.confidence_score > 0 && (
                                             <span className={`text-[10px] px-2 py-0.5 rounded font-semibold ${theme === 'dark' ? 'bg-emerald-900/40 text-emerald-400' : 'bg-emerald-100 text-emerald-600'}`}>
                                                {Math.round(h.confidence_score)}% conf
                                             </span>
                                          )}
                                       </div>
                                       <p className={`text-sm font-mono truncate ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`} title={h.target}>{h.target}</p>
                                       <div className={`flex items-center gap-3 mt-1.5 text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>
                                          {h.stats && (
                                             <span className="flex items-center gap-1">
                                                {h.stats.critical > 0 && <span className="text-red-400 font-bold">{h.stats.critical}C</span>}
                                                {h.stats.high > 0 && <span className="text-orange-400">{h.stats.high}H</span>}
                                                {h.stats.medium > 0 && <span className="text-yellow-400">{h.stats.medium}M</span>}
                                                {h.stats.low > 0 && <span className="text-blue-400">{h.stats.low}L</span>}
                                                {totalVulns === 0 && <span className="text-emerald-400">✓ Clean</span>}
                                             </span>
                                          )}
                                          <span>⏱ {durationMin}</span>
                                          {h.successful_analyses !== undefined && (
                                             <span>{h.successful_analyses} analyses</span>
                                          )}
                                       </div>
                                    </div>
                                    {/* Rerun button: prefill config from history entry */}
                                    <button
                                       onClick={() => {
                                          if (h.target) setTarget(h.target);
                                          if (h.profile) setProfile(h.profile);
                                          if (h.mode) setScanMode(h.mode);
                                          setShowHistory(false);
                                          setView('config');
                                          toast.success('Configuration pré-remplie depuis l\'historique');
                                       }}
                                       className={`shrink-0 flex items-center gap-1 text-xs px-3 py-1.5 rounded-lg border transition-colors ${theme === 'dark'
                                          ? 'bg-indigo-600/10 border-indigo-500/30 text-indigo-400 hover:bg-indigo-600/20'
                                          : 'bg-indigo-50 border-indigo-200 text-indigo-600 hover:bg-indigo-100'
                                          }`}
                                       title="Relancer avec cette configuration"
                                    >
                                       <RotateCcw size={11} /> Rerun
                                    </button>
                                 </div>
                              </div>
                           );
                        })}
                     </div>
                  </div>
               </div>
            )}

            {/* === LOGS MODAL (V3.1) === */}
            {showLogs && (
               <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-6 animate-in fade-in duration-200">
                  <div className="w-full max-w-5xl h-[700px] flex flex-col rounded-2xl shadow-2xl overflow-hidden bg-slate-950 border border-slate-800">

                     <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/50 text-slate-200">
                        <div className="flex items-center gap-3">
                           <div className="p-2 bg-indigo-500/10 rounded-lg">
                              <Terminal size={18} className="text-indigo-400" />
                           </div>
                           <div>
                              <h3 className="font-bold text-sm">Logs d'exécution</h3>
                              <p className="text-xs text-slate-500 font-mono">{status.logs.length} entrées • {status.estimated_time}</p>
                           </div>
                        </div>
                        <button
                           onClick={() => setShowLogs(false)}
                           className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
                        >
                           <XCircle size={20} />
                        </button>
                     </div>

                     <div className="flex-1 bg-slate-950 p-6 overflow-y-auto font-mono text-xs space-y-1.5 custom-scrollbar selection:bg-indigo-500/30">
                        {status.logs.map((log, i) => {
                           // Style intelligent selon le contenu du log (V3.1 Explainable)
                           const isFiltered = log.msg.includes('🗑️ Filtered');
                           const isPrudent = log.msg.includes('⚠️ Prudent');
                           const isCritical = log.msg.includes('🚨');

                           let txColor = 'text-slate-300';
                           if (log.type === 'success') txColor = 'text-emerald-400';
                           else if (log.type === 'error' || isCritical) txColor = 'text-red-400 font-bold';
                           else if (log.type === 'warning' || isPrudent) txColor = 'text-yellow-400';
                           else if (isFiltered) txColor = 'text-slate-500 italic'; // Grisé pour les filtres

                           return (
                              <div key={i} className={`flex gap-4 p-1 rounded hover:bg-white/5 transition-colors ${isFiltered ? 'opacity-60 hover:opacity-100' : ''}`}>
                                 <span className="text-slate-600 shrink-0 select-none w-16 text-right">[{log.time}]</span>
                                 <span className={`${txColor} break-all`}>
                                    {log.msg}
                                 </span>
                              </div>
                           );
                        })}
                     </div>
                  </div>
               </div>
            )}
         </main>

         {/* GLOBAL CSS */}
         <style>{`
            .custom-scrollbar::-webkit-scrollbar { width: 6px; height: 6px; }
            .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
            .custom-scrollbar::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }
            .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #64748b; }
            .no-scrollbar::-webkit-scrollbar { display: none; }
         `}</style>
      </div>
   );
}

// === PREFLIGHT VIEW COMPONENT ===

// Static warning hints map — avoids dynamic class generation
const WARNING_HINTS = {
   'Remote URL seems proxied': 'Les proxies Cloudflare (524) peuvent couper les connexions longues (>100s). Préférez une connexion directe ou réduisez le timeout read.',
   'Eco profile with model > 8B': 'Le profil Eco est optimisé pour des modèles légers (≤8B). Accuracy-first: passez en Balanced ou Elite pour des modèles plus grands.',
   'Target is remote or unavailable': 'Le dépôt distant n\'a pas pu être cloné pour l\'estimation. Les stats sont partielles; la taille réelle peut différer.',
   'Repo very large': 'Dépôt volumineux (>5000 fichiers ou >500 Mo). Le mode Deep peut être très lent; envisagez d\'exclure des dossiers inutiles ou de passer sur serveur dédié.',
   'Ollama endpoint is not reachable': 'Le backend ne peut pas joindre Ollama. Vérifiez que le service est démarré et que l\'URL est correcte (mode auto = localhost:11434).',
};

function getWarningHint(w) {
   const key = Object.keys(WARNING_HINTS).find(k => w.includes(k));
   return key ? WARNING_HINTS[key] : null;
}

function PreflightView({ data, target, profile, scanMode, theme, onBack, onStart }) {
   const [expandedHint, setExpandedHint] = React.useState(null);

   const card = `rounded-xl border p-5 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`;
   const lbl = `text-xs font-semibold uppercase tracking-wider ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`;
   const val = `text-sm font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-slate-800'}`;
   const dimTxt = `text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`;

   const { repo_stats: rs, profile_effective: pe, ollama_context: oc, warnings = [] } = data;

   const fmtBytes = (b) => {
      if (!b) return '0 B';
      if (b < 1024) return `${b} B`;
      if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
      return `${(b / (1024 * 1024)).toFixed(1)} MB`;
   };

   const PF_MODE_LABELS = { rapid: 'Rapide', deep: 'Profond', devsecops: 'DevSecOps' };
   const PF_PROFILE_LABELS = { eco: 'Eco', balanced: 'Balanced', elite: 'Elite', titan: 'Titan' };

   const isEco = profile === 'eco';
   const coverageRatio = rs.total_files > 0 ? Math.round((rs.analyzable_files / rs.total_files) * 100) : 0;

   return (
      <div className="max-w-4xl mx-auto space-y-5">
         {/* Header */}
         <div>
            <h2 className="text-xl font-bold flex items-center gap-2">
               <Layers className="w-5 h-5 text-indigo-400" />
               Preflight — Revue pré-scan
            </h2>
            <p className={`text-sm mt-1 font-mono truncate max-w-xl ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>
               {target} &nbsp;·&nbsp; {PF_PROFILE_LABELS[profile] || profile} &nbsp;·&nbsp; {PF_MODE_LABELS[scanMode] || scanMode}
            </p>
         </div>

         {/* Warnings — per-item with expandable hint */}
         {warnings.length > 0 && (
            <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/10 p-4 space-y-2">
               <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
                  <p className="text-sm font-semibold text-yellow-400">{warnings.length} avertissement{warnings.length > 1 ? 's' : ''}</p>
               </div>
               {warnings.map((w, i) => {
                  const hint = getWarningHint(w);
                  const isOpen = expandedHint === i;
                  return (
                     <div key={i} className={`rounded-lg border px-3 py-2 ${theme === 'dark' ? 'bg-slate-900/60 border-slate-800' : 'bg-white border-slate-200'}`}>
                        <div className="flex items-start gap-2">
                           <span className={`text-xs flex-1 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>• {w}</span>
                           {hint && (
                              <button
                                 onClick={() => setExpandedHint(isOpen ? null : i)}
                                 className={`text-[10px] shrink-0 px-1.5 py-0.5 rounded border transition-colors ${isOpen
                                    ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400'
                                    : theme === 'dark' ? 'border-slate-700 text-slate-500 hover:text-slate-300' : 'border-slate-300 text-slate-500 hover:text-slate-700'
                                 }`}
                                 title="Pourquoi ?"
                              >
                                 Pourquoi ?
                              </button>
                           )}
                        </div>
                        {isOpen && hint && (
                           <p className={`text-[11px] mt-1.5 leading-relaxed ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{hint}</p>
                        )}
                     </div>
                  );
               })}
            </div>
         )}

         <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Repo Stats */}
            <div className={card}>
               <div className="flex items-center gap-2 mb-4">
                  <Database className="w-4 h-4 text-indigo-400" />
                  <h3 className="text-sm font-semibold">Dépôt</h3>
                  <span className={`ml-auto text-xs font-mono px-2 py-0.5 rounded ${theme === 'dark' ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'}`}>
                     {fmtBytes(rs.total_bytes_est)}
                  </span>
               </div>

               {/* Coverage bar */}
               <div className="mb-4">
                  <div className="flex justify-between text-xs mb-1">
                     <span className={dimTxt}>Couverture d'analyse</span>
                     <span className="font-semibold text-emerald-400">{coverageRatio}%</span>
                  </div>
                  <div className={`h-2 rounded-full overflow-hidden ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>
                     <div className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-500" style={{ width: `${coverageRatio}%` }} />
                  </div>
                  <div className="flex justify-between mt-1">
                     <span className={`${dimTxt} text-indigo-400`}>{rs.analyzable_files} analysables</span>
                     <span className={dimTxt}>{rs.excluded_files} exclus / {rs.total_files} total</span>
                  </div>
               </div>

               {rs.excluded_reasons && rs.excluded_reasons.length > 0 && (
                  <div>
                     <p className={`${lbl} mb-2`}>Top exclusions</p>
                     <ul className="space-y-1">
                        {rs.excluded_reasons.slice(0, 5).map((r, i) => {
                           const pct = rs.excluded_files > 0 ? Math.round((r.count / rs.excluded_files) * 100) : 0;
                           return (
                              <li key={i} className="flex items-center gap-2">
                                 <span className={`text-xs flex-1 truncate ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{r.reason}</span>
                                 <div className="flex items-center gap-1.5">
                                    <div className={`w-12 h-1 rounded-full overflow-hidden ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>
                                       <div className="h-full bg-slate-500 rounded-full" style={{ width: `${pct}%` }} />
                                    </div>
                                    <span className={`text-[10px] font-mono w-6 text-right ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>{r.count}</span>
                                 </div>
                              </li>
                           );
                        })}
                     </ul>
                  </div>
               )}
            </div>

            {/* Profile Effective */}
            <div className={card}>
               <div className="flex items-center gap-2 mb-4">
                  <Cpu className="w-4 h-4 text-violet-400" />
                  <h3 className="text-sm font-semibold">Profil effectif</h3>
                  <span className={`ml-auto text-xs px-2 py-0.5 rounded border ${theme === 'dark' ? 'border-violet-500/30 bg-violet-500/10 text-violet-400' : 'border-violet-300 bg-violet-50 text-violet-600'}`}>
                     {PF_PROFILE_LABELS[pe.profile_name] || pe.profile_name}
                  </span>
               </div>
               <div className="space-y-2.5">
                  {[
                     { k: 'Chunk tokens',    v: pe.target_chunk_tokens?.toLocaleString(), tip: 'Taille max d\'un bloc de code analysé par l\'IA' },
                     { k: 'Timeout connect', v: `${pe.connect_timeout_s}s`,               tip: 'Délai d\'établissement de la connexion Ollama' },
                     { k: 'Timeout read',    v: `${pe.read_timeout_s}s`,                  tip: 'Délai max pour recevoir la réponse complète' },
                     { k: 'Concurrence',     v: pe.max_concurrency,                       tip: 'Nombre de fichiers analysés en parallèle' },
                     { k: 'Timeout global',  v: `${Math.round(pe.global_scan_timeout_s / 60)} min`, tip: 'Durée max totale du scan avant interruption' },
                     { k: 'Evidence stricte',v: pe.strict_evidence ? 'Oui' : 'Non',       tip: 'Si Oui, toute vulnérabilité sans preuve de code est ignorée' },
                  ].map(({ k, v, tip }) => (
                     <div key={k} className="flex items-center justify-between gap-3" title={tip}>
                        <span className={`${lbl} cursor-help`}>{k}</span>
                        <span className={val}>{v}</span>
                     </div>
                  ))}
               </div>
               {isEco && (
                  <div className={`mt-3 p-2 rounded-lg text-[11px] flex items-start gap-2 ${theme === 'dark' ? 'bg-emerald-900/30 text-emerald-400 border border-emerald-800/40' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}`}>
                     <span className="shrink-0">💡</span>
                     <span><strong>Eco · Accuracy-first:</strong> chunks plus petits, timeout court. Résultats solides mais moins exhaustifs que Elite/Titan.</span>
                  </div>
               )}
            </div>

            {/* Ollama Context */}
            <div className={card}>
               <div className="flex items-center gap-2 mb-4">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold">Ollama</h3>
                  <span className={`ml-auto flex items-center gap-1 text-xs px-2 py-0.5 rounded border font-medium ${oc.reachable
                     ? theme === 'dark' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-emerald-300 bg-emerald-50 text-emerald-600'
                     : theme === 'dark' ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-red-300 bg-red-50 text-red-600'
                  }`}>
                     {oc.reachable ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                     {oc.reachable ? 'Joignable' : 'Hors ligne'}
                  </span>
               </div>
               <div className="space-y-2.5">
                  {[
                     { k: 'Mode',    v: oc.mode === 'local' ? 'Local (auto)' : 'Distant' },
                     { k: 'URL',     v: oc.base_url },
                     { k: 'Modèle', v: oc.model },
                  ].map(({ k, v }) => (
                     <div key={k} className="flex items-center justify-between gap-4">
                        <span className={lbl}>{k}</span>
                        <span className={`text-xs font-mono truncate max-w-[200px] ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{v || '—'}</span>
                     </div>
                  ))}
               </div>
               {oc.tags && oc.tags.length > 0 && (
                  <div className="mt-3">
                     <p className={`${lbl} mb-1.5`}>Modèles dispo</p>
                     <div className="flex flex-wrap gap-1">
                        {oc.tags.slice(0, 6).map((t, i) => (
                           <span key={i} className={`text-[10px] px-2 py-0.5 rounded font-mono ${theme === 'dark' ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-600'}`}>{t}</span>
                        ))}
                        {oc.tags.length > 6 && (
                           <span className={`text-[10px] px-2 py-0.5 rounded ${theme === 'dark' ? 'bg-slate-800 text-slate-500' : 'bg-slate-100 text-slate-500'}`}>+{oc.tags.length - 6}</span>
                        )}
                     </div>
                  </div>
               )}
               {!oc.reachable && (
                  <p className="mt-3 text-xs text-red-400 flex items-start gap-1.5">
                     <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                     Non joignable — vérifiez que le service Ollama est actif avant de lancer.
                  </p>
               )}
            </div>

            {/* Launch summary */}
            <div className={`${card} flex flex-col justify-between gap-4`}>
               <div>
                  <div className="flex items-center gap-2 mb-3">
                     <CheckCircle className="w-4 h-4 text-emerald-400" />
                     <h3 className="text-sm font-semibold">Récapitulatif</h3>
                  </div>
                  <div className="space-y-2">
                     {[
                        { k: 'Fichiers à analyser', v: `${rs.analyzable_files} (${coverageRatio}% du dépôt)`, color: 'text-emerald-400' },
                        { k: 'Profil',              v: `${PF_PROFILE_LABELS[pe.profile_name] || pe.profile_name}${isEco ? ' · accuracy-first' : ''}`, color: theme === 'dark' ? 'text-slate-200' : 'text-slate-800' },
                        { k: 'Mode',                v: PF_MODE_LABELS[scanMode] || scanMode, color: theme === 'dark' ? 'text-slate-200' : 'text-slate-800' },
                        { k: 'Timeout max',         v: `${Math.round(pe.global_scan_timeout_s / 60)} min`, color: theme === 'dark' ? 'text-slate-200' : 'text-slate-800' },
                     ].map(({ k, v, color }) => (
                        <div key={k} className="flex items-center justify-between">
                           <span className={lbl}>{k}</span>
                           <span className={`text-xs font-semibold ${color}`}>{v}</span>
                        </div>
                     ))}
                  </div>
               </div>
               {warnings.length === 0 && oc.reachable && (
                  <div className={`flex items-center gap-2 text-xs px-3 py-2 rounded-lg ${theme === 'dark' ? 'bg-emerald-900/20 text-emerald-400 border border-emerald-800/30' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}`}>
                     <CheckCircle className="w-3 h-3 shrink-0" />
                     Tout est prêt — aucun avertissement.
                  </div>
               )}
            </div>
         </div>

         {/* CTA */}
         <div className={`flex items-center justify-between pt-4 border-t ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
            <button
               onClick={onBack}
               className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium border transition-all ${theme === 'dark'
                  ? 'bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-300'
                  : 'bg-white hover:bg-slate-50 border-slate-300 text-slate-700'
               }`}
            >
               <ArrowLeft className="w-4 h-4" /> Retour config
            </button>

            <div className="flex items-center gap-3">
               {!oc.reachable && (
                  <span className="text-xs text-red-400 flex items-center gap-1">
                     <AlertTriangle className="w-3 h-3" /> Ollama hors ligne
                  </span>
               )}
               <button
                  onClick={onStart}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-2.5 rounded-xl font-medium shadow-lg shadow-indigo-600/20 transition-all flex items-center gap-2"
               >
                  <Shield className="w-4 h-4" /> Démarrer l'Audit
               </button>
            </div>
         </div>
      </div>
   );
}

// === FINDING LIST ITEM ===

function FindingListItem({ finding: f, selected, onSelect, theme }) {
   const severity = (() => {
      const n = f.severity?.toUpperCase();
      return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(n) ? n : 'LOW';
   })();
   const SevIcon = SEVERITY_STYLES[severity].icon;
   return (
      <div
         onClick={onSelect}
         className={`p-3 rounded-lg cursor-pointer border transition-all hover:bg-slate-50 dark:hover:bg-slate-800/50 ${selected
            ? 'bg-indigo-50 dark:bg-slate-800 border-indigo-500 dark:border-indigo-500'
            : 'bg-transparent border-transparent'
         }`}
      >
         <div className="flex justify-between items-center mb-1">
            <div className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${SEVERITY_STYLES[severity].badge} flex items-center gap-1`}>
               <SevIcon size={9} />
               {f.severity}
            </div>
            <span className="text-slate-500 text-[10px] font-mono">#{f.id}</span>
         </div>
         <h4 className={`font-semibold text-xs line-clamp-2 ${theme === 'dark' ? 'text-slate-200' : 'text-slate-800'}`}>{f.title}</h4>
         <div className="text-[10px] text-slate-500 mt-0.5 truncate">{(f.file || f.filepath || '').split('/').pop()}</div>
      </div>
   );
}

// === HELPER COMPONENTS ===

function StatCard({ title, count, color, icon, theme }) {
   const colors = {
      red: theme === 'dark' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-red-100 border-red-300 text-red-600',
      orange: theme === 'dark' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' : 'bg-orange-100 border-orange-300 text-orange-600',
      yellow: theme === 'dark' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400' : 'bg-yellow-100 border-yellow-300 text-yellow-600',
      blue: theme === 'dark' ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' : 'bg-blue-100 border-blue-300 text-blue-600',
   };

   return (
      <div className={`rounded-xl border p-4 ${colors[color]}`}>
         <div className="text-center">
            <div className="text-2xl mb-1">{icon}</div>
            <div className="text-2xl font-bold">{count}</div>
            <div className="text-xs font-semibold uppercase tracking-wider opacity-70">{title}</div>
         </div>
      </div>
   );
}

function TabButton({ active, onClick, icon, label, count, theme }) {
   return (
      <button
         onClick={onClick}
         className={`flex items-center gap-2 pb-3 px-1 text-sm font-medium transition-all border-b-2 ${active
            ? 'border-indigo-500 text-indigo-400'
            : theme === 'dark'
               ? 'border-transparent text-slate-500 hover:text-slate-300'
               : 'border-transparent text-slate-600 hover:text-slate-900'
            }`}
      >
         {icon}
         {label}
         {count !== undefined && (
            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${theme === 'dark' ? 'bg-slate-800 text-slate-400' : 'bg-slate-200 text-slate-600'}`}>
               {count}
            </span>
         )}
      </button>
   );
}

function SeverityBadge({ level, theme, icon }) {
   const colors = {
      'Critical': theme === 'dark' ? 'bg-red-500/10 border-red-500/20 text-red-400' : 'bg-red-100 border-red-300 text-red-600',
      'High': theme === 'dark' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' : 'bg-orange-100 border-orange-300 text-orange-600',
      'Medium': theme === 'dark' ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400' : 'bg-yellow-100 border-yellow-300 text-yellow-600',
      'Low': theme === 'dark' ? 'bg-blue-500/10 border-blue-500/20 text-blue-400' : 'bg-blue-100 border-blue-300 text-blue-600',
   };

   return (
      <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wide border ${colors[level] || colors.Low}`}>
         {icon} {level}
      </span>
   );
}