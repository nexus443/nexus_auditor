import React from 'react';
import { AlertOctagon, Wrench } from 'lucide-react';

// Import SEVERITY_STYLES from App (we'll pass it as prop instead)
const SEVERITY_STYLES = {
    CRITICAL: { badge: 'bg-red-500/10 text-red-500 border-red-500/20' },
    HIGH: { badge: 'bg-orange-500/10 text-orange-500 border-orange-500/20' },
    MEDIUM: { badge: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' },
    LOW: { badge: 'bg-blue-500/10 text-blue-500 border-blue-500/20' },
};

// Executive View Component
const ExecutiveView = ({ vulnerabilities, stats, theme }) => {
    // Top 5 risks by severity + confidence
    const topRisks = [...vulnerabilities]
        .sort((a, b) => {
            const sevOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
            const sevDiff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
            if (sevDiff !== 0) return sevDiff;
            return (b.confidence || 0) - (a.confidence || 0);
        })
        .slice(0, 5);

    // Remediation Plan (P0/P1/P2)
    const getFixTimeMinutes = (severity) => {
        const times = { Critical: 180, High: 90, Medium: 45, Low: 20 };
        return times[severity] || 30;
    };

    const remediationPlan = [
        {
            priority: 'P0',
            label: 'Critical - Immediate Action',
            vulns: vulnerabilities.filter(v => v.severity === 'Critical'),
            color: 'red',
            time: vulnerabilities.filter(v => v.severity === 'Critical').reduce((sum, v) => sum + getFixTimeMinutes(v.severity), 0)
        },
        {
            priority: 'P1',
            label: 'High - This Sprint',
            vulns: vulnerabilities.filter(v => v.severity === 'High'),
            color: 'orange',
            time: vulnerabilities.filter(v => v.severity === 'High').reduce((sum, v) => sum + getFixTimeMinutes(v.severity), 0)
        },
        {
            priority: 'P2',
            label: 'Medium/Low - Next Sprint',
            vulns: vulnerabilities.filter(v => v.severity === 'Medium' || v.severity === 'Low'),
            color: 'yellow',
            time: vulnerabilities.filter(v => v.severity === 'Medium' || v.severity === 'Low').reduce((sum, v) => sum + getFixTimeMinutes(v.severity), 0)
        }
    ];

    const priorityStyles = {
        red: { bg: 'bg-red-500/10', border: 'border-red-500', text: 'text-red-500' },
        orange: { bg: 'bg-orange-500/10', border: 'border-orange-500', text: 'text-orange-500' },
        yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500', text: 'text-yellow-500' }
    };

    return (
        <div className="space-y-6">
            {/* Risk Overview */}
            <div className={`rounded-xl border p-6 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                    <AlertOctagon className="w-5 h-5 text-red-500" />
                    Security Risk Overview
                </h3>
                <div className="grid grid-cols-4 gap-4">
                    {['Critical', 'High', 'Medium', 'Low'].map(sev => {
                        const count = stats[sev.toLowerCase()] || 0;
                        const sevStyle = SEVERITY_STYLES[sev.toUpperCase()];
                        return (
                            <div key={sev} className={`p-4 rounded-lg border ${sevStyle.badge}`}>
                                <div className="text-3xl font-bold mb-1">{count}</div>
                                <div className="text-xs font-medium uppercase tracking-wide">{sev}</div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Top 5 Risks */}
            <div className={`rounded-xl border p-6 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                <h3 className="text-lg font-bold mb-4">Top 5 Critical Findings</h3>
                <div className="space-y-3">
                    {topRisks.map((v, i) => {
                        const sevStyle = SEVERITY_STYLES[v.severity.toUpperCase()];
                        return (
                            <div key={i} className={`p-4 rounded-lg border ${sevStyle.badge}`}>
                                <div className="flex items-start justify-between mb-2">
                                    <div className="flex-1">
                                        <h4 className="font-semibold text-sm mb-1">{v.title}</h4>
                                        <p className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{v.file}</p>
                                    </div>
                                    <div className={`px-2 py-1 rounded text-xs font-bold ${sevStyle.badge}`}>
                                        {v.severity}
                                    </div>
                                </div>
                                <p className={`text-xs ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{v.description?.substring(0, 150)}...</p>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Remediation Plan */}
            <div className={`rounded-xl border p-6 ${theme === 'dark' ? 'bg-slate-900 border-slate-800' : 'bg-white border-slate-200'}`}>
                <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                    <Wrench className="w-5 h-5 text-indigo-400" />
                    Remediation Roadmap
                </h3>
                <div className="space-y-4">
                    {remediationPlan.map(plan => {
                        const style = priorityStyles[plan.color];
                        const hours = Math.ceil(plan.time / 60);
                        return (
                            <div key={plan.priority} className={`p-4 rounded-lg border ${style.bg} ${style.border}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div>
                                        <span className={`font-bold ${style.text}`}>{plan.priority}</span>
                                        <span className={`ml-2 text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{plan.label}</span>
                                    </div>
                                    <div className="text-right">
                                        <div className={`text-2xl font-bold ${style.text}`}>{plan.vulns.length}</div>
                                        <div className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>~{hours}h to fix</div>
                                    </div>
                                </div>
                                {plan.vulns.length > 0 && (
                                    <div className={`text-xs mt-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
                                        {plan.vulns.slice(0, 3).map(v => v.title).join(' • ')}
                                        {plan.vulns.length > 3 && ` • +${plan.vulns.length - 3} more`}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};

export default ExecutiveView;
