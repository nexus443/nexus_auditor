import React, { useState, useEffect, useRef } from 'react';
import {
   Shield, Search, Activity, FileText, Terminal, AlertTriangle,
   CheckCircle, XCircle, ChevronRight, Bug, X, Code, Clock,
   Download, History, Zap, Layers, Server, Sun, Moon, Filter, ChevronDown,
   TrendingUp, Wrench, BookOpen, GitCompare, Sparkles, AlertOctagon, Copy
} from 'lucide-react';
import { useToasts } from './components/Toast.jsx';
import ExecutiveView from './components/ExecutiveView.jsx';

const API_URL = "/api";

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
   const [view, setView] = useState('config'); // 'config' | 'running' | 'results'

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

   // Legacy states (kept for compatibility)
   const [searchQuery, setSearchQuery] = useState("");
   const [selectedSeverities, setSelectedSeverities] = useState([]);
   const [selectedFiles, setSelectedFiles] = useState([]);
   const [showFilters, setShowFilters] = useState(false);
   const [selectedVuln, setSelectedVuln] = useState(null);
   const [expandedCards, setExpandedCards] = useState(new Set());
   const [history, setHistory] = useState([]);
   const [autoFixLoading, setAutoFixLoading] = useState(null);
   const logEndRef = useRef(null);

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

   // Log filtering for advanced log viewer
   const [logFilter, setLogFilter] = useState('all'); // 'all' | 'info' | 'warn' | 'error'

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
      let interval;
      if (status.is_scanning || status.progress > 0) {
         interval = setInterval(async () => {
            try {
               const res = await fetch(`${API_URL}/scan/status`);
               const data = await res.json();
               setStatus(data);

               // Auto-switch to results view when scan completes
               if (!data.is_scanning && data.progress === 100 && view === 'running') {
                  setView('results');
               }

               if (view === 'running' && activeTab === 'logs') scrollToBottom();
            } catch (e) { console.error(e); }
         }, 1000);
      }
      return () => clearInterval(interval);
   }, [status.is_scanning, view, activeTab]);

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

   const scrollToBottom = () => logEndRef.current?.scrollIntoView({ behavior: "smooth" });

   const startScan = async () => {
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
      try {
         const res = await fetch(`${API_URL}/fix/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vuln_id: vulnId })
         });
         const data = await res.json();

         if (data.success) {
            toast.success(`Patch généré: ${data.patch_file}`, 8000);
            window.open(`${API_URL}/fix/download/${data.patch_file}`, '_blank');
         } else {
            toast.error(`Échec génération patch: ${data.error}`);
         }
      } catch (e) {
         toast.error('Erreur lors de la génération du patch');
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
   const filteredFindings = resultsFilter === 'ALL'
      ? status.vulnerabilities
      : status.vulnerabilities.filter(v => v.severity.toUpperCase() === resultsFilter);

   // Apply search filter
   const searchedFindings = resultsSearch
      ? filteredFindings.filter(v =>
         v.title?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.file?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.description?.toLowerCase().includes(resultsSearch.toLowerCase()) ||
         v.type?.toLowerCase().includes(resultsSearch.toLowerCase())
      )
      : filteredFindings;

   const copyJSON = (obj) => {
      navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
      toast.success('JSON copié dans le presse-papier');
   };

   // Normalize severity for SEVERITY_STYLES mapping
   const normalizeSeverity = (sev) => {
      const normalized = sev?.toUpperCase();
      return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(normalized) ? normalized : 'LOW';
   };

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

                           <button onClick={startScan} className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-2.5 rounded-xl font-medium shadow-lg shadow-indigo-600/20 transition-all flex items-center gap-2">
                              <Shield className="w-4 h-4" /> Démarrer l'Audit
                           </button>
                        </div>
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

            {/* === RUNNING VIEW (Claude logs + live stats) === */}
            {view === 'running' && (
               <div className="space-y-6">
                  {/* Progress Card */}
                  <div className={`rounded-2xl border p-6 shadow-xl ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                     <div className="flex justify-between items-end mb-4">
                        <div>
                           <h2 className="text-lg font-bold flex items-center gap-2">
                              <Activity className="text-indigo-500 animate-pulse" />
                              Scan en cours...
                           </h2>
                           <p className={`font-mono text-sm mt-1 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{status.current_file}</p>
                        </div>
                        <div className="text-right">
                           <div className="text-2xl font-bold font-mono text-indigo-500">{Math.round(status.progress)}%</div>
                           <div className="text-xs text-slate-400">Temps estimé: <span className="text-slate-300">{status.estimated_time}</span></div>
                        </div>
                     </div>
                     <div className={`h-2 rounded-full overflow-hidden ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>
                        <div
                           className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300 ease-out"
                           style={{ width: `${status.progress}%` }}
                        />
                     </div>
                  </div>

                  {/* Pipeline Stages Timeline */}
                  <div className="mb-6">
                     <div className={`rounded-xl border p-4 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                        <div className="flex items-center gap-2 mb-3">
                           <Layers className="w-4 h-4 text-indigo-400" />
                           <h3 className="text-sm font-semibold">Pipeline Progress</h3>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                           {[
                              { label: 'Normalize', icon: '📋', stage: 1 },
                              { label: 'Index', icon: '🔍', stage: 2 },
                              { label: 'Analyze', icon: '🧠', stage: 3 },
                              { label: 'Correlate', icon: '🔗', stage: 4 },
                              { label: 'Report', icon: '📊', stage: 5 }
                           ].map((s, i) => {
                              // Heuristic: deduce stage from progress
                              const currentStage = Math.ceil((status.progress / 100) * 5);
                              const isActive = currentStage === s.stage;
                              const isDone = currentStage > s.stage;

                              return (
                                 <div key={i} className="flex-1">
                                    <div className={`text-center p-2 rounded-lg border transition-all ${isDone
                                       ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500'
                                       : isActive
                                          ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400 animate-pulse'
                                          : theme === 'dark' ? 'bg-slate-800 border-slate-700 text-slate-500' : 'bg-slate-100 border-slate-300 text-slate-400'
                                       }`}>
                                       <div className="text-lg mb-1">{s.icon}</div>
                                       <div className="text-xs font-medium">{s.label}</div>
                                       {isDone && <div className="text-[10px] mt-0.5">✓</div>}
                                       {isActive && <div className="text-[10px] mt-0.5">...</div>}
                                    </div>
                                    {i < 4 && (
                                       <div className={`h-0.5 mt-2 ${isDone ? 'bg-emerald-500' : 'bg-slate-700'}`} />
                                    )}
                                 </div>
                              );
                           })}
                        </div>
                     </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                     {/* Terminal */}
                     <div className="lg:col-span-2">
                        <div className="bg-slate-950 rounded-xl border border-slate-800 h-[400px] flex flex-col font-mono text-xs overflow-hidden shadow-2xl">
                           <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
                              <div className="flex items-center gap-2 text-slate-400">
                                 <Terminal size={14} /> Output Console
                              </div>
                              <div className="flex items-center gap-2">
                                 {/* Log Filters */}
                                 <div className="flex items-center gap-1 bg-slate-900 rounded px-1">
                                    {['all', 'info', 'warn', 'error'].map(f => (
                                       <button
                                          key={f}
                                          onClick={() => setLogFilter(f)}
                                          className={`px-2 py-0.5 text-[10px] rounded transition-all ${logFilter === f
                                             ? 'bg-indigo-600 text-white'
                                             : 'text-slate-500 hover:text-slate-300'
                                             }`}
                                       >
                                          {f.toUpperCase()}
                                       </button>
                                    ))}
                                 </div>
                                 {/* Download Logs */}
                                 <button
                                    onClick={() => {
                                       const logText = status.logs.map(l => `[${l.time}] ${l.msg}`).join('\n');
                                       const blob = new Blob([logText], { type: 'text/plain' });
                                       const url = URL.createObjectURL(blob);
                                       const a = document.createElement('a');
                                       a.href = url;
                                       a.download = `nexus-scan-logs-${Date.now()}.txt`;
                                       a.click();
                                       URL.revokeObjectURL(url);
                                       toast.success('Logs téléchargés');
                                    }}
                                    className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-white transition-colors"
                                    title="Download logs"
                                 >
                                    <Download size={12} />
                                 </button>
                              </div>
                           </div>
                           <div className="flex-1 p-4 overflow-y-auto space-y-1 custom-scrollbar">
                              {status.logs.filter(log => {
                                 if (logFilter === 'all') return true;
                                 const msg = log.msg.toLowerCase();
                                 if (logFilter === 'info') return !msg.includes('⚠️') && !msg.includes('❌') && !msg.includes('error');
                                 if (logFilter === 'warn') return msg.includes('⚠️') || msg.includes('warning');
                                 if (logFilter === 'error') return msg.includes('❌') || msg.includes('error') || msg.includes('critical');
                                 return true;
                              }).map((log, i) => (
                                 <div
                                    key={i}
                                    className="flex gap-3 opacity-90 hover:bg-slate-900/50 p-0.5 group"
                                    onClick={() => {
                                       navigator.clipboard.writeText(`[${log.time}] ${log.msg}`);
                                       toast.success('Log copié');
                                    }}
                                    title="Click to copy"
                                 >
                                    <span className="text-slate-600 shrink-0">[{log.time}]</span>
                                    <span className={log.type === 'success' ? 'text-emerald-400' : 'text-slate-300'}>
                                       {log.type === 'success' ? '✔ ' : '> '} {log.msg}
                                    </span>
                                    <Copy className="w-3 h-3 text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity ml-auto" />
                                 </div>
                              ))}
                              <div ref={logEndRef} />
                           </div>
                        </div>
                     </div>

                     {/* Live Stats */}
                     <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                           <div className={`p-4 rounded-xl border ${SEVERITY_STYLES.CRITICAL.badge} flex flex-col items-center justify-center bg-opacity-5`}>
                              <span className="text-3xl font-bold mb-1">{status.stats.critical}</span>
                              <span className="text-[10px] font-bold uppercase tracking-widest opacity-80">CRITICAL</span>
                           </div>
                           <div className={`p-4 rounded-xl border ${SEVERITY_STYLES.HIGH.badge} flex flex-col items-center justify-center bg-opacity-5`}>
                              <span className="text-3xl font-bold mb-1">{status.stats.high}</span>
                              <span className="text-[10px] font-bold uppercase tracking-widest opacity-80">HIGH</span>
                           </div>
                           <div className={`p-4 rounded-xl border ${SEVERITY_STYLES.MEDIUM.badge} flex flex-col items-center justify-center bg-opacity-5`}>
                              <span className="text-3xl font-bold mb-1">{status.stats.medium}</span>
                              <span className="text-[10px] font-bold uppercase tracking-widest opacity-80">MEDIUM</span>
                           </div>
                           <div className={`p-4 rounded-xl border bg-slate-500/10 text-slate-500 border-slate-500/20 flex flex-col items-center justify-center bg-opacity-5`}>
                              <span className="text-3xl font-bold mb-1">{status.stats.critical + status.stats.high + status.stats.medium + status.stats.low}</span>
                              <span className="text-[10px] font-bold uppercase tracking-widest opacity-80">TOTAL</span>
                           </div>
                        </div>
                        <button onClick={stopScan} className="w-full bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 px-4 py-2.5 rounded-xl font-medium transition-all flex items-center justify-center gap-2">
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
                        <div className="flex-1 grid grid-cols-12 gap-6 min-h-0">
                           {/* LISTE GAUCHE - TECHNICAL VIEW */}
                           <div className={`col-span-4 flex flex-col overflow-hidden rounded-xl border ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                              <div className={`p-4 border-b flex gap-2 overflow-x-auto no-scrollbar ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                                 <button
                                    onClick={() => setResultsFilter('ALL')}
                                    className={`px-3 py-1 rounded text-xs font-bold transition-colors ${resultsFilter === 'ALL' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800'}`}
                                 >
                                    ALL
                                 </button>
                                 {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                                    <button
                                       key={sev}
                                       onClick={() => setResultsFilter(sev)}
                                       className={`px-3 py-1 rounded text-xs font-bold transition-colors ${resultsFilter === sev ? SEVERITY_STYLES[sev].badge : 'text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800'}`}
                                    >
                                       {sev}
                                    </button>
                                 ))}
                              </div>

                              {/* Search bar */}
                              <div className={`p-3 border-b ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                                 <div className="relative">
                                    <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
                                    <input
                                       type="text"
                                       value={resultsSearch}
                                       onChange={(e) => setResultsSearch(e.target.value)}
                                       placeholder="Rechercher..."
                                       className={`w-full pl-9 pr-3 py-2 text-sm rounded-lg border ${theme === 'dark'
                                          ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500'
                                          : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400'
                                          } focus:outline-none focus:ring-1`}
                                    />
                                 </div>
                              </div>

                              <div className="flex-1 overflow-y-auto p-2 space-y-2 custom-scrollbar">
                                 {searchedFindings.length === 0 && (
                                    <div className="text-center p-8 text-slate-500 text-sm">Aucun résultat pour ce filtre.</div>
                                 )}
                                 {searchedFindings.map(f => {
                                    const severity = normalizeSeverity(f.severity);
                                    const SevIcon = SEVERITY_STYLES[severity].icon;
                                    return (
                                       <div
                                          key={f.id}
                                          onClick={() => setSelectedVulnId(f.id)}
                                          className={`p-4 rounded-lg cursor-pointer border transition-all hover:bg-slate-50 dark:hover:bg-slate-800/50 ${selectedVulnId === f.id
                                             ? 'bg-indigo-50 dark:bg-slate-800 border-indigo-500 dark:border-indigo-500'
                                             : 'bg-transparent border-transparent'
                                             }`}
                                       >
                                          <div className="flex justify-between items-start mb-2">
                                             <div className={`text-[10px] font-bold px-2 py-0.5 rounded border ${SEVERITY_STYLES[severity].badge} flex items-center gap-1`}>
                                                <SevIcon size={10} />
                                                {f.severity}
                                             </div>
                                             <span className="text-slate-400 text-xs font-mono">#{f.id}</span>
                                          </div>
                                          <h4 className={`font-semibold text-sm line-clamp-1 ${theme === 'dark' ? 'text-slate-200' : 'text-slate-800'}`}>{f.title}</h4>
                                          <div className="text-xs text-slate-500 mt-1 truncate">{f.file || f.filepath}</div>
                                       </div>
                                    );
                                 })}
                              </div>
                           </div>

                           {/* DETAIL DROITE */}
                           <div className={`col-span-8 flex flex-col overflow-hidden rounded-xl ${theme === 'dark' ? 'bg-[#0B1120]' : 'bg-slate-50'}`}>
                              {selectedFinding ? (
                                 <div className="flex-1 overflow-y-auto p-8 custom-scrollbar">
                                    <div className="flex items-start gap-4 mb-6">
                                       {React.createElement(SEVERITY_STYLES[normalizeSeverity(selectedFinding.severity)].icon, {
                                          size: 32,
                                          className: `p-3 rounded-xl border ${SEVERITY_STYLES[normalizeSeverity(selectedFinding.severity)].badge} bg-opacity-10`
                                       })}
                                       <div className="flex-1">
                                          <h2 className={`text-xl font-bold ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>{selectedFinding.title}</h2>
                                          <div className={`flex items-center gap-4 mt-2 text-sm font-mono ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'}`}>
                                             <span className="flex items-center gap-1"><FileText size={14} /> {selectedFinding.file || selectedFinding.filepath}</span>
                                             {(selectedFinding.line || selectedFinding.line_start) && (
                                                <>
                                                   <span>:</span>
                                                   <span className="flex items-center gap-1">
                                                      Ligne{selectedFinding.line_end ? 's' : ''} {selectedFinding.line || selectedFinding.line_start}
                                                      {selectedFinding.line_end && `–${selectedFinding.line_end}`}
                                                   </span>
                                                </>
                                             )}
                                             {selectedFinding.confidence && (
                                                <>
                                                   <span>•</span>
                                                   <span className={selectedFinding.confidence >= 70 ? 'text-emerald-400' : selectedFinding.confidence >= 40 ? 'text-yellow-400' : 'text-red-400'}>
                                                      {selectedFinding.confidence}% confiance
                                                   </span>
                                                </>
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
                                          <Copy size={16} />
                                       </button>
                                    </div>

                                    <div className="space-y-8">
                                       {/* V3.1: Manual Review Note / Evidence Missing */}
                                       {(selectedFinding.note || selectedFinding.needs_manual_review) && (
                                          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 flex items-start gap-3">
                                             <AlertTriangle className="text-yellow-500 shrink-0 mt-0.5" size={18} />
                                             <div>
                                                <h3 className="text-yellow-500 font-bold text-sm mb-1">Attention requise</h3>
                                                <p className={`text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
                                                   {selectedFinding.note || "Examen manuel requis (Preuve manquante)"}
                                                </p>
                                             </div>
                                          </div>
                                       )}
                                       {/* Description */}
                                       <div>
                                          <h3 className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-2">Analyse Technique</h3>
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

                                       {/* Code Snippet */}
                                       {selectedFinding.snippet && selectedFinding.snippet !== "Code non disponible" && (
                                          <div>
                                             <h3 className="text-xs font-bold uppercase text-slate-500 tracking-wider mb-2">Evidence (Code Source)</h3>
                                             <div className="bg-[#1e1e1e] rounded-lg border border-slate-800 overflow-hidden font-mono text-sm shadow-inner">
                                                <div className="flex items-center justify-between px-4 py-2 bg-[#252526] border-b border-slate-800 text-xs text-slate-400">
                                                   <span>{selectedFinding.file || selectedFinding.filepath}</span>
                                                   <span>RO mode</span>
                                                </div>
                                                <pre className="p-4 overflow-x-auto text-slate-300">
                                                   <code>{selectedFinding.snippet}</code>
                                                </pre>
                                             </div>
                                          </div>
                                       )}

                                       {/* Remediation */}
                                       {selectedFinding.fix && (
                                          <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-xl p-6">
                                             <h3 className="text-emerald-500 font-bold flex items-center gap-2 mb-2">
                                                <Wrench size={18} /> Recommandation
                                             </h3>
                                             <p className={`text-sm mb-4 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
                                                {selectedFinding.fix}
                                             </p>
                                             <div className="flex gap-3">
                                                <button
                                                   onClick={() => generateFix(selectedFinding.id)}
                                                   disabled={autoFixLoading === selectedFinding.id || !((selectedFinding.file || selectedFinding.filepath) && (selectedFinding.line || selectedFinding.line_start) && selectedFinding.fix && selectedFinding.fix !== "Pas de correctif proposé.")}
                                                   className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs py-1.5 px-4 h-8 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                                >
                                                   {autoFixLoading === selectedFinding.id ? '⏳ Génération...' : '🔧 Générer correctif'}
                                                </button>
                                             </div>
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
                     )
                  )}
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