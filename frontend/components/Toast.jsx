import React, { createContext, useContext, useState, useEffect } from 'react';
import { CheckCircle, XCircle, Info, X } from 'lucide-react';

const ToastContext = createContext();

export const useToasts = () => {
    const context = useContext(ToastContext);
    if (!context) {
        throw new Error('useToasts must be used within ToastProvider');
    }
    return context;
};

export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);

    const addToast = (message, type = 'info', duration = 5000) => {
        const id = Date.now() + Math.random();
        setToasts(prev => [...prev, { id, message, type, duration }]);

        if (duration > 0) {
            setTimeout(() => removeToast(id), duration);
        }
    };

    const removeToast = (id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    };

    const toast = {
        success: (msg, duration) => addToast(msg, 'success', duration),
        error: (msg, duration) => addToast(msg, 'error', duration),
        info: (msg, duration) => addToast(msg, 'info', duration),
    };

    return (
        <ToastContext.Provider value={toast}>
            {children}
            <ToastHost toasts={toasts} onRemove={removeToast} />
        </ToastContext.Provider>
    );
};

const ToastHost = ({ toasts, onRemove }) => {
    return (
        <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none">
            {toasts.map(toast => (
                <Toast key={toast.id} {...toast} onClose={() => onRemove(toast.id)} />
            ))}
        </div>
    );
};

const Toast = ({ message, type, onClose }) => {
    const styles = {
        success: {
            bg: 'bg-emerald-500/90',
            icon: CheckCircle,
            border: 'border-emerald-400'
        },
        error: {
            bg: 'bg-red-500/90',
            icon: XCircle,
            border: 'border-red-400'
        },
        info: {
            bg: 'bg-blue-500/90',
            icon: Info,
            border: 'border-blue-400'
        }
    };

    const style = styles[type] || styles.info;
    const Icon = style.icon;

    return (
        <div
            className={`${style.bg} ${style.border} border backdrop-blur-md text-white px-4 py-3 rounded-lg shadow-xl flex items-center gap-3 min-w-[320px] max-w-md pointer-events-auto animate-slide-in`}
        >
            <Icon className="w-5 h-5 flex-shrink-0" />
            <p className="flex-1 text-sm font-medium">{message}</p>
            <button
                onClick={onClose}
                className="flex-shrink-0 hover:bg-white/20 rounded p-1 transition-colors"
                aria-label="Close"
            >
                <X className="w-4 h-4" />
            </button>
        </div>
    );
};
