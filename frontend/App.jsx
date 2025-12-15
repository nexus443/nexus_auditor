import React, { useState, useEffect, useRef } from 'react';
import {
   Shield, Search, Activity, FileText, Terminal, AlertTriangle,
   CheckCircle, XCircle, ChevronRight, Bug, X, Code, Clock,
   Download, History, Zap, Layers, Server, Sun, Moon, Filter, ChevronDown,
   TrendingUp, Wrench, BookOpen, GitCompare, Sparkles
} from 'lucide-react';

const API_URL = "/api";

export default function App() {
   const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark');

   const [activeTab, setActiveTab] = useState('scan');
   const [target, setTarget] = useState("");
   const [profile, setProfile] = useState("balanced");
   const [scanMode, setScanMode] = useState("deep");
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

   const [searchQuery, setSearchQuery] = useState("");
   const [selectedSeverities, setSelectedSeverities] = useState([]);
   const [selectedFiles, setSelectedFiles] = useState([]);
   const [showFilters, setShowFilters] = useState(false);

   const [selectedVuln, setSelectedVuln] = useState(null);
   const [expandedCards, setExpandedCards] = useState(new Set());
   const [history, setHistory] = useState([]);
   const [autoFixLoading, setAutoFixLoading] = useState(null);
   const logEndRef = useRef(null);

   useEffect(() => {
      localStorage.setItem('theme', theme);
      document.documentElement.setAttribute('data-theme', theme);
   }, [theme]);

   useEffect(() => {
      let interval;
      if (status.is_scanning || status.progress > 0) {
         interval = setInterval(async () => {
            try {
               const res = await fetch(`${API_URL}/scan/status`);
               const data = await res.json();
               setStatus(data);
               if (data.is_scanning && activeTab === 'logs') scrollToBottom();
            } catch (e) { console.error(e); }
         }, 1000);
      }
      return () => clearInterval(interval);
   }, [status.is_scanning, activeTab]);

   useEffect(() => {
      loadHistory();
   }, []);

   const loadHistory = async () => {
      try {
         const res = await fetch(`${API_URL}/history`);
         const data = await res.json();
         setHistory(data);
      } catch (e) { console.error(e); }
   };

   const scrollToBottom = () => logEndRef.current?.scrollIntoView({ behavior: "smooth" });

   const startScan = async () => {
      if (!target) return alert("Veuillez entrer une cible !");
      try {
         await fetch(`${API_URL}/scan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, profile, mode: scanMode })
         });
         setStatus(prev => ({ ...prev, is_scanning: true, progress: 1 }));
         setActiveTab('logs');
      } catch (e) { alert("Backend hors ligne"); }
   };

   const stopScan = async () => fetch(`${API_URL}/scan/stop`, { method: 'POST' });

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
            alert(`✅ Patch généré !\n\nFichier: ${data.patch_file}\n\nAvant: ${data.preview.before}\nAprès: ${data.preview.after}`);
            window.open(`${API_URL}/fix/download/${data.patch_file}`, '_blank');
         } else {
            alert(`❌ Échec: ${data.error}`);
         }
      } catch (e) {
         alert("Erreur lors de la génération du patch");
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

   return (
      <div className={`min-h-screen transition-colors duration-300 ${theme === 'dark'
         ? 'bg-slate-950 text-slate-100'
         : 'bg-slate-50 text-slate-900'
         } font-sans selection:bg-indigo-500/30`}>

         {/* HEADER */}
         <header className={`border-b sticky top-0 z-20 backdrop-blur-md ${theme === 'dark'
            ? 'border-slate-800 bg-slate-900/50'
            : 'border-slate-200 bg-white/50'
            }`}>
            <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
               <div className="flex items-center gap-3">
                  <div className="bg-gradient-to-br from-indigo-600 to-violet-600 p-2 rounded-lg shadow-lg">
                     <Shield className="w-6 h-6 text-white" />
                  </div>
                  <div>
                     <h1 className="text-xl font-bold tracking-tight leading-none">Nexus <span className="text-indigo-400">Auditor</span></h1>
                     <span className={`text-xs font-medium tracking-wider ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>ENTERPRISE EDITION V2.2</span>
                  </div>
               </div>

               <div className="flex items-center gap-4">
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

                  {status.progress === 100 && (
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

            {/* CONFIGURATION PANEL */}
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
                              onChange={(e) => setTarget(e.target.value)}
                              placeholder="https://github.com/company/repo.git"
                              className={`w-full border rounded-xl py-3 pl-12 pr-4 focus:outline-none focus:ring-1 transition-all font-mono text-sm ${theme === 'dark'
                                 ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500 focus:ring-indigo-500'
                                 : 'bg-slate-50 border-slate-300 text-slate-900 focus:border-indigo-400 focus:ring-indigo-400'
                                 }`}
                           />
                        </div>
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
                           <label className={`block text-xs font-semibold uppercase tracking-wider mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                              }`}>Mode de Scan</label>
                           <div className="flex gap-2">
                              <button onClick={() => setScanMode('rapid')} className={`flex-1 p-2 rounded-lg border transition-all flex justify-center items-center ${scanMode === 'rapid' ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400' : theme === 'dark' ? 'bg-slate-950 border-slate-800 text-slate-500' : 'bg-slate-100 border-slate-300 text-slate-600'}`} title="Rapide">
                                 <Zap className="w-5 h-5" />
                              </button>
                              <button onClick={() => setScanMode('deep')} className={`flex-1 p-2 rounded-lg border transition-all flex justify-center items-center ${scanMode === 'deep' ? 'bg-indigo-500/10 border-indigo-500 text-indigo-400' : theme === 'dark' ? 'bg-slate-950 border-slate-800 text-slate-500' : 'bg-slate-100 border-slate-300 text-slate-600'}`} title="Profond">
                                 <Layers className="w-5 h-5" />
                              </button>
                              <button onClick={() => setScanMode('devsecops')} className={`flex-1 p-2 rounded-lg border transition-all flex justify-center items-center ${scanMode === 'devsecops' ? 'bg-orange-500/10 border-orange-500 text-orange-400' : theme === 'dark' ? 'bg-slate-950 border-slate-800 text-slate-500' : 'bg-slate-100 border-slate-300 text-slate-600'}`} title="DevSecOps">
                                 <Server className="w-5 h-5" />
                              </button>
                           </div>
                        </div>
                     </div>

                     <div className={`pt-4 flex items-center justify-between border-t ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'
                        }`}>
                        <div className={`flex items-center gap-4 text-sm font-mono ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'
                           }`}>
                           <span className="flex items-center gap-1.5"><Clock className="w-4 h-4 text-indigo-400" /> {status.estimated_time}</span>
                        </div>

                        {status.is_scanning ? (
                           <button onClick={stopScan} className="bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/50 px-8 py-2.5 rounded-xl font-medium transition-all flex items-center gap-2">
                              <XCircle className="w-4 h-4" /> STOP
                           </button>
                        ) : (
                           <button onClick={startScan} className="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-2.5 rounded-xl font-medium shadow-lg shadow-indigo-600/20 transition-all flex items-center gap-2">
                              <Shield className="w-4 h-4" /> Démarrer l'Audit
                           </button>
                        )}
                     </div>
                  </div>

                  {status.progress > 0 && (
                     <div className={`absolute bottom-0 left-0 w-full h-1 ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>
                        <div className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300" style={{ width: `${status.progress}%` }}></div>
                     </div>
                  )}
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

            {/* TABS NAVIGATION */}
            <div className={`flex gap-6 border-b mb-6 ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
               <TabButton active={activeTab === 'scan'} onClick={() => setActiveTab('scan')} icon={<Terminal className="w-4 h-4" />} label="Live Console" theme={theme} />
               <TabButton active={activeTab === 'detections'} onClick={() => setActiveTab('detections')} icon={<Bug className="w-4 h-4" />} label="Résultats" count={status.vulnerabilities.length} theme={theme} />
               <TabButton active={activeTab === 'guided'} onClick={() => setActiveTab('guided')} icon={<TrendingUp className="w-4 h-4" />} label="Analyse Guidée" theme={theme} />
               <TabButton active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} icon={<History className="w-4 h-4" />} label="Logs Système" theme={theme} />
            </div>

            {/* TAB CONTENT */}
            <div className="min-h-[400px]">

               {/* LOGS TERMINAL */}
               {(activeTab === 'scan' || activeTab === 'logs') && (
                  <div className={`rounded-xl border p-4 font-mono text-sm h-[500px] overflow-y-auto shadow-inner custom-scrollbar ${theme === 'dark'
                     ? 'bg-slate-950 border-slate-800'
                     : 'bg-slate-50 border-slate-200'
                     }`}>
                     {status.logs.length === 0 ? <div className={`text-center mt-20 ${theme === 'dark' ? 'text-slate-600' : 'text-slate-400'}`}>Prêt...</div> : (
                        status.logs.map((log, i) => (
                           <div key={i} className={`flex gap-3 p-0.5 rounded transition-colors ${theme === 'dark' ? 'hover:bg-slate-900/50' : 'hover:bg-slate-100'
                              }`}>
                              <span className={theme === 'dark' ? 'text-slate-600' : 'text-slate-400'}>[{log.time}]</span>
                              <span className={log.type === 'error' ? 'text-red-400' : log.type === 'success' ? 'text-emerald-400' : theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}>{log.msg}</span>
                           </div>
                        ))
                     )}
                     <div ref={logEndRef} />
                  </div>
               )}

               {/* GUIDED ANALYSIS */}
               {activeTab === 'guided' && (
                  <div className="space-y-6">
                     <div className={`rounded-xl border p-6 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                        <div className="flex items-center gap-3 mb-4">
                           <Sparkles className="w-6 h-6 text-indigo-400" />
                           <h2 className="text-xl font-bold">Analyse Guidée par IA</h2>
                        </div>

                        {getTopVulnerabilities().length === 0 ? (
                           <div className="text-center py-10">
                              <CheckCircle className={`w-16 h-16 mx-auto mb-4 ${theme === 'dark' ? 'text-slate-700' : 'text-slate-300'}`} />
                              <p className={theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}>Aucune vulnérabilité à analyser</p>
                           </div>
                        ) : (
                           <>
                              <div className={`rounded-lg p-4 mb-6 border-l-4 border-indigo-500 ${theme === 'dark' ? 'bg-indigo-500/10' : 'bg-indigo-50'}`}>
                                 <h3 className="font-semibold mb-2 text-indigo-400">🎯 Top 5 Failles Prioritaires</h3>
                                 <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                                    Ordre recommandé de correction : de la plus critique à la moins critique
                                 </p>
                              </div>

                              <div className="space-y-4">
                                 {getTopVulnerabilities().map((vuln, index) => (
                                    <div key={vuln.id} className={`rounded-xl border p-5 ${theme === 'dark' ? 'bg-slate-800 border-slate-700' : 'bg-slate-50 border-slate-200'}`}>
                                       <div className="flex items-start justify-between mb-3">
                                          <div className="flex items-start gap-4 flex-1">
                                             <div className="text-3xl font-bold text-slate-600">#{index + 1}</div>
                                             <div className="flex-1">
                                                <div className="flex items-center gap-2 mb-2">
                                                   <SeverityBadge level={vuln.severity} theme={theme} icon={severityIcons[vuln.severity]} />
                                                   <h4 className="font-semibold">{vuln.title}</h4>
                                                </div>
                                                <div className={`text-sm mb-3 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                                                   📁 {vuln.file} : Ligne {vuln.line || 'N/A'}
                                                </div>

                                                {/* Business Impact */}
                                                <div className={`rounded-lg p-3 mb-3 ${theme === 'dark' ? 'bg-slate-900' : 'bg-white'}`}>
                                                   <div className="grid grid-cols-2 gap-3 text-sm">
                                                      <div>
                                                         <span className={`font-semibold ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Impact Business:</span>
                                                         <p className="mt-1">{getBusinessImpact(vuln.severity, vuln.type)}</p>
                                                      </div>
                                                      <div>
                                                         <span className={`font-semibold ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Temps estimé:</span>
                                                         <p className="mt-1">⏱️ {getEstimatedFixTime(vuln.severity)}</p>
                                                      </div>
                                                   </div>
                                                </div>

                                                {/* Auto-fix button */}
                                                <button
                                                   onClick={() => generateFix(vuln.id)}
                                                   disabled={autoFixLoading === vuln.id}
                                                   className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                                >
                                                   {autoFixLoading === vuln.id ? (
                                                      <>⏳ Génération...</>
                                                   ) : (
                                                      <><Wrench className="w-4 h-4" /> Générer Correctif</>
                                                   )}
                                                </button>
                                             </div>
                                          </div>
                                       </div>
                                    </div>
                                 ))}
                              </div>
                           </>
                        )}
                     </div>
                  </div>
               )}

               {/* DETECTIONS LIST WITH FILTERS */}
               {activeTab === 'detections' && (
                  <div className="space-y-4">
                     <div className="flex gap-4">
                        <div className="flex-1 relative">
                           <Search className="absolute left-4 top-3.5 w-5 h-5 text-slate-400" />
                           <input
                              type="text"
                              value={searchQuery}
                              onChange={(e) => setSearchQuery(e.target.value)}
                              placeholder="Rechercher vulnérabilités, fichiers, code..."
                              className={`w-full border rounded-xl py-3 pl-12 pr-4 focus:outline-none focus:ring-1 transition-all text-sm ${theme === 'dark'
                                 ? 'bg-slate-950 border-slate-700 text-slate-200 focus:border-indigo-500 focus:ring-indigo-500'
                                 : 'bg-white border-slate-300 text-slate-900 focus:border-indigo-400 focus:ring-indigo-400'
                                 }`}
                           />
                        </div>

                        <button
                           onClick={() => setShowFilters(!showFilters)}
                           className={`flex items-center gap-2 px-4 py-3 rounded-xl border transition-all ${showFilters
                              ? 'bg-indigo-600/10 border-indigo-500 text-indigo-400'
                              : theme === 'dark'
                                 ? 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600'
                                 : 'bg-white border-slate-300 text-slate-600 hover:border-slate-400'
                              }`}
                        >
                           <Filter className="w-5 h-5" />
                           Filtres
                           <ChevronDown className={`w-4 h-4 transition-transform ${showFilters ? 'rotate-180' : ''}`} />
                        </button>
                     </div>

                     {showFilters && (
                        <div className={`rounded-xl border p-4 space-y-4 ${theme === 'dark'
                           ? 'bg-slate-900 border-slate-800'
                           : 'bg-white border-slate-200'
                           }`}>
                           <div>
                              <h4 className={`text-sm font-semibold mb-2 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Gravité</h4>
                              <div className="flex flex-wrap gap-2">
                                 {['Critical', 'High', 'Medium', 'Low'].map(sev => (
                                    <button
                                       key={sev}
                                       onClick={() => toggleSeverity(sev)}
                                       className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition-all ${selectedSeverities.includes(sev)
                                          ? `bg-${sev === 'Critical' ? 'red' : sev === 'High' ? 'orange' : sev === 'Medium' ? 'yellow' : 'green'}-500/20 border-${sev === 'Critical' ? 'red' : sev === 'High' ? 'orange' : sev === 'Medium' ? 'yellow' : 'green'}-500 text-${sev === 'Critical' ? 'red' : sev === 'High' ? 'orange' : sev === 'Medium' ? 'yellow' : 'green'}-400`
                                          : theme === 'dark'
                                             ? 'bg-slate-800 border-slate-700 text-slate-400'
                                             : 'bg-slate-100 border-slate-300 text-slate-600'
                                          }`}
                                    >
                                       {severityIcons[sev]} {sev}
                                    </button>
                                 ))}
                              </div>
                           </div>

                           {uniqueFiles.length > 0 && (
                              <div>
                                 <h4 className={`text-sm font-semibold mb-2 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>Fichiers ({uniqueFiles.length})</h4>
                                 <div className="flex flex-wrap gap-2 max-h-32 overflow-y-auto">
                                    {uniqueFiles.map(file => (
                                       <button
                                          key={file}
                                          onClick={() => toggleFile(file)}
                                          className={`px-3 py-1 rounded-lg text-xs font-medium border transition-all ${selectedFiles.includes(file)
                                             ? 'bg-indigo-600/20 border-indigo-500 text-indigo-400'
                                             : theme === 'dark'
                                                ? 'bg-slate-800 border-slate-700 text-slate-400'
                                                : 'bg-slate-100 border-slate-300 text-slate-600'
                                             }`}
                                       >
                                          {file}
                                       </button>
                                    ))}
                                 </div>
                              </div>
                           )}

                           {(selectedSeverities.length > 0 || selectedFiles.length > 0 || searchQuery) && (
                              <button
                                 onClick={() => {
                                    setSelectedSeverities([]);
                                    setSelectedFiles([]);
                                    setSearchQuery('');
                                 }}
                                 className="text-sm text-indigo-400 hover:text-indigo-300 transition-colors"
                              >
                                 Réinitialiser les filtres
                              </button>
                           )}
                        </div>
                     )}

                     <div className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                        {filteredVulns.length} résultat{filteredVulns.length !== 1 ? 's' : ''}
                        {filteredVulns.length !== status.vulnerabilities.length && ` (sur ${status.vulnerabilities.length})`}
                     </div>

                     {/* Vulnerability Cards */}
                     <div className="space-y-3">
                        {filteredVulns.length === 0 ? (
                           <div className={`text-center py-20 border border-dashed rounded-xl ${theme === 'dark' ? 'border-slate-800' : 'border-slate-300'
                              }`}>
                              <CheckCircle className={`w-12 h-12 mx-auto mb-4 ${theme === 'dark' ? 'text-slate-700' : 'text-slate-300'}`} />
                              <p className={theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}>
                                 {status.vulnerabilities.length === 0
                                    ? 'Aucune vulnérabilité trouvée.'
                                    : 'Aucun résultat pour ces filtres.'}
                              </p>
                           </div>
                        ) : (
                           filteredVulns.map((vuln) => {
                              const isExpanded = expandedCards.has(vuln.id);
                              const reasoning = vuln.reasoning || {};

                              return (
                                 <div
                                    key={vuln.id}
                                    className={`rounded-xl border p-4 transition-all ${theme === 'dark'
                                       ? 'bg-slate-900 border-slate-800 hover:border-indigo-500/50'
                                       : 'bg-white border-slate-200 hover:border-indigo-400/50'
                                       }`}
                                 >
                                    <div
                                       onClick={() => toggleCardExpand(vuln.id)}
                                       className="flex justify-between items-start cursor-pointer"
                                    >
                                       <div className="flex gap-4 flex-1">
                                          <SeverityBadge level={vuln.severity} theme={theme} icon={severityIcons[vuln.severity]} />
                                          <div className="flex-1">
                                             <h3 className={`font-semibold transition-colors ${theme === 'dark'
                                                ? 'text-slate-200 group-hover:text-indigo-400'
                                                : 'text-slate-800 group-hover:text-indigo-500'
                                                }`}>{vuln.title}</h3>
                                             <div className={`flex gap-2 text-sm mt-1 font-mono ${theme === 'dark' ? 'text-slate-500' : 'text-slate-600'
                                                }`}>
                                                <span>{vuln.file}</span>:<span>L{vuln.line || 'N/A'}</span>
                                                {vuln.confidence && (
                                                   <span className="ml-2 text-xs">
                                                      Confiance: <span className={vuln.confidence >= 70 ? 'text-emerald-400' : vuln.confidence >= 40 ? 'text-yellow-400' : 'text-red-400'}>{vuln.confidence}%</span>
                                                   </span>
                                                )}
                                             </div>
                                          </div>
                                       </div>
                                       <ChevronRight className={`transition-transform ${isExpanded ? 'rotate-90' : ''} ${theme === 'dark' ? 'text-slate-600' : 'text-slate-400'}`} />
                                    </div>

                                    {isExpanded && (
                                       <div className="mt-4 space-y-4 animate-fade-in">
                                          <div>
                                             <h4 className={`text-xs font-bold uppercase tracking-wide mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>Description</h4>
                                             <p className={`p-3 rounded-lg border text-sm ${theme === 'dark'
                                                ? 'bg-slate-800/50 border-slate-800 text-slate-300'
                                                : 'bg-slate-50 border-slate-200 text-slate-700'
                                                }`}>{vuln.description || 'Pas de description'}</p>
                                          </div>

                                          {/* AI Profiling Section */}
                                          {(reasoning.pattern || reasoning.cve_refs?.length > 0 || reasoning.exploit_example) && (
                                             <div className={`rounded-lg border-l-4 border-indigo-500 p-4 ${theme === 'dark' ? 'bg-indigo-500/10' : 'bg-indigo-50'}`}>
                                                <h4 className="text-sm font-bold text-indigo-400 mb-3 flex items-center gap-2">
                                                   <BookOpen className="w-4 h-4" /> 🧠 Profilage IA
                                                </h4>
                                                <div className="space-y-2 text-sm">
                                                   {reasoning.pattern && reasoning.pattern !== 'Non spécifié' && (
                                                      <div>
                                                         <span className="font-semibold">Pattern détecté:</span> {reasoning.pattern}
                                                      </div>
                                                   )}
                                                   {reasoning.cve_refs && reasoning.cve_refs.length > 0 && (
                                                      <div>
                                                         <span className="font-semibold">CVE Références:</span> {reasoning.cve_refs.join(', ')}
                                                      </div>
                                                   )}
                                                   {reasoning.exploit_example && reasoning.exploit_example !== 'Non fourni' && (
                                                      <div>
                                                         <span className="font-semibold">Scénario d'exploitation:</span> {reasoning.exploit_example}
                                                      </div>
                                                   )}
                                                </div>
                                             </div>
                                          )}

                                          {vuln.snippet && (
                                             <div>
                                                <h4 className="text-xs font-bold text-red-400 uppercase tracking-wide mb-2 flex items-center gap-2">
                                                   <FileText className="w-3 h-3" /> Code Vulnérable
                                                </h4>
                                                <div className={`rounded-lg border overflow-hidden ${theme === 'dark' ? 'bg-[#0d1117] border-slate-800' : 'bg-slate-900 border-slate-700'
                                                   }`}>
                                                   <div className={`flex items-center justify-between px-3 py-1 border-b text-xs ${theme === 'dark' ? 'bg-slate-900 border-slate-800 text-slate-500' : 'bg-slate-800 border-slate-700 text-slate-400'
                                                      }`}>
                                                      <span>{vuln.file}</span>
                                                      <span>Ligne {vuln.line}</span>
                                                   </div>
                                                   <pre className="p-4 font-mono text-sm text-slate-300 overflow-x-auto whitespace-pre">
                                                      {vuln.snippet}
                                                   </pre>
                                                </div>
                                             </div>
                                          )}

                                          <div>
                                             <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wide mb-2 flex items-center gap-2">
                                                <Code className="w-3 h-3" /> Correctif Suggéré
                                             </h4>
                                             <div className={`rounded-lg border p-4 font-mono text-sm overflow-x-auto ${theme === 'dark'
                                                ? 'bg-[#0d1117] border-emerald-900/30 text-emerald-300'
                                                : 'bg-emerald-50 border-emerald-200 text-emerald-800'
                                                }`}>
                                                {vuln.fix || 'Pas de correctif proposé'}
                                             </div>
                                          </div>

                                          {vuln.cve_reference && (
                                             <div className={`p-3 rounded-lg border text-sm ${theme === 'dark'
                                                ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                                                : 'bg-yellow-50 border-yellow-200 text-yellow-700'
                                                }`}>
                                                🔗 Référence: <strong>{vuln.cve_reference}</strong>
                                             </div>
                                          )}

                                          {/* Auto-Fix Button */}
                                          <div className="pt-3 border-t border-slate-700">
                                             <button
                                                onClick={() => generateFix(vuln.id)}
                                                disabled={autoFixLoading === vuln.id}
                                                className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                             >
                                                {autoFixLoading === vuln.id ? (
                                                   <>⏳ Génération du patch...</>
                                                ) : (
                                                   <><Wrench className="w-4 h-4" /> Générer Patch de Correction</>
                                                )}
                                             </button>
                                          </div>
                                       </div>
                                    )}
                                 </div>
                              );
                           })
                        )}
                     </div>
                  </div>
               )}
            </div>
         </main>
      </div>
   );
}

function StatCard({ title, count, color, icon, theme }) {
   const colors = {
      red: "bg-red-500/10 text-red-500 border-red-500/20",
      orange: "bg-orange-500/10 text-orange-500 border-orange-500/20",
      yellow: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
      blue: "bg-blue-500/10 text-blue-500 border-blue-500/20",
   };
   const lightColors = {
      red: "bg-red-50 text-red-600 border-red-200",
      orange: "bg-orange-50 text-orange-600 border-orange-200",
      yellow: "bg-yellow-50 text-yellow-600 border-yellow-200",
      blue: "bg-blue-50 text-blue-600 border-blue-200",
   };

   return (
      <div className={`p-4 rounded-xl border flex flex-col items-center justify-center ${theme === 'dark' ? colors[color] : lightColors[color]}`}>
         <div className="text-2xl mb-1">{icon}</div>
         <span className="text-2xl font-bold mb-1">{count}</span>
         <span className="text-xs font-medium opacity-80 uppercase tracking-wide">{title}</span>
      </div>
   );
}

function TabButton({ active, onClick, icon, label, count, theme }) {
   return (
      <button onClick={onClick} className={`pb-3 px-2 text-sm font-medium flex items-center gap-2 border-b-2 transition-all ${active ? 'border-indigo-500 text-indigo-400' : `border-transparent ${theme === 'dark' ? 'text-slate-500 hover:text-slate-300' : 'text-slate-600 hover:text-slate-800'}`}`}>
         {icon} {label}
         {count !== undefined && <span className={`text-xs px-2 py-0.5 rounded-full ${theme === 'dark' ? 'bg-slate-800' : 'bg-slate-200'}`}>{count}</span>}
      </button>
   );
}

function SeverityBadge({ level, theme, icon }) {
   const darkColors = {
      'Critical': 'bg-red-500/20 text-red-400 border-red-500/30',
      'High': 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      'Medium': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      'Low': 'bg-green-500/20 text-green-400 border-green-500/30'
   };
   const lightColors = {
      'Critical': 'bg-red-50 text-red-600 border-red-200',
      'High': 'bg-orange-50 text-orange-600 border-orange-200',
      'Medium': 'bg-yellow-50 text-yellow-600 border-yellow-200',
      'Low': 'bg-green-50 text-green-600 border-green-200'
   };

   const c = theme === 'dark' ? darkColors[level] : lightColors[level];
   return <span className={`px-2 py-0.5 rounded text-xs font-bold border ${c} uppercase flex items-center gap-1 shrink-0`}>{icon} {level}</span>;
}