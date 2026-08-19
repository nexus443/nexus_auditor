import React, { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { CheckCircle, Info, X, XCircle } from 'lucide-react'

import { cn } from '@/lib/utils'

const ToastContext = createContext(null)

export const useToasts = () => {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToasts must be used within ToastProvider')
  }
  return context
}

export const ToastProvider = ({ children }) => {
  const [toasts, setToasts] = useState([])

  const removeToast = useCallback((id) => {
    setToasts((previous) => previous.filter((t) => t.id !== id))
  }, [])

  const addToast = useCallback(
    (message, type = 'info', duration = 5000) => {
      const id = Date.now() + Math.random()
      setToasts((previous) => [...previous, { id, message, type, duration }])

      if (duration > 0) {
        setTimeout(() => removeToast(id), duration)
      }
    },
    [removeToast],
  )

  const toast = useMemo(
    () => ({
      success: (msg, duration) => addToast(msg, 'success', duration),
      error: (msg, duration) => addToast(msg, 'error', duration),
      info: (msg, duration) => addToast(msg, 'info', duration),
    }),
    [addToast],
  )

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <ToastHost toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  )
}

const ToastHost = ({ toasts, onRemove }) => (
  <div className="pointer-events-none fixed right-4 top-4 z-[100] flex max-w-[calc(100vw-2rem)] flex-col gap-2">
    {toasts.map((toast) => (
      <Toast key={toast.id} {...toast} onClose={() => onRemove(toast.id)} />
    ))}
  </div>
)

const STYLES = {
  success: { ring: 'ring-success/30', accent: 'text-success', icon: CheckCircle },
  error: { ring: 'ring-critical/30', accent: 'text-critical', icon: XCircle },
  info: { ring: 'ring-primary/30', accent: 'text-primary', icon: Info },
}

const Toast = ({ message, type, onClose }) => {
  const style = STYLES[type] || STYLES.info
  const Icon = style.icon

  return (
    <div
      role="status"
      className={cn(
        'pointer-events-auto flex w-full min-w-[280px] items-center gap-3 rounded-xl border border-border bg-card px-4 py-3 shadow-lg ring-1 animate-slide-in sm:min-w-[320px] sm:max-w-md',
        style.ring,
      )}
    >
      <Icon className={cn('h-5 w-5 shrink-0', style.accent)} />
      <p className="min-w-0 flex-1 break-words text-sm font-medium">{message}</p>
      <button
        type="button"
        onClick={onClose}
        className="shrink-0 rounded p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        aria-label="Fermer"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}
