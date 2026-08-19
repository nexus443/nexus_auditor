import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Command, Cpu, Menu, Moon, Plus, Search, Sun } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { SidebarNav } from './SidebarNav'
import { useNexus } from '@/hooks/useNexus.jsx'
import { cn } from '@/lib/utils'

export function Topbar() {
  const { theme, setTheme, health, runtime } = useNexus()
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const [query, setQuery] = useState('')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  // ⌘K / Ctrl+K : focus sur la recherche globale.
  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        inputRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const submit = (event) => {
    event.preventDefault()
    navigate(query.trim() ? `/results?q=${encodeURIComponent(query.trim())}` : '/results')
  }

  const profileName = runtime.data?.profile_effective?.profile_name
  const model = runtime.data?.ollama_context?.model

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-background/70 px-4 md:px-6 backdrop-blur-xl">
      <Sheet open={mobileNavOpen} onOpenChange={setMobileNavOpen}>
        <SheetTrigger asChild>
          <Button variant="ghost" size="icon" className="md:hidden" aria-label="Ouvrir la navigation">
            <Menu className="h-4 w-4" />
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="flex w-72 flex-col bg-sidebar p-0">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarNav onNavigate={() => setMobileNavOpen(false)} />
        </SheetContent>
      </Sheet>

      <form onSubmit={submit} className="relative flex-1 max-w-xl">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          ref={inputRef}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Rechercher une vulnérabilité, un fichier…"
          aria-label="Rechercher dans les résultats"
          className="h-10 w-full rounded-md border border-border bg-card/50 pl-9 pr-16 text-sm placeholder:text-muted-foreground/70 outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-primary/20"
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 hidden md:inline-flex items-center gap-1 rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
          <Command className="h-3 w-3" /> K
        </kbd>
      </form>

      <div className="ml-auto flex items-center gap-2">
        {(profileName || model) && (
          <div className="hidden lg:flex items-center gap-2 rounded-md border border-border bg-card/50 px-2.5 py-1.5 text-xs text-muted-foreground">
            <Cpu className="h-3.5 w-3.5 text-primary" />
            {model && <span className="font-mono">{model}</span>}
            {model && profileName && <span className="opacity-60">·</span>}
            {profileName && <span className="capitalize">Profil {profileName}</span>}
          </div>
        )}

        <span
          className={cn(
            'hidden sm:inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium',
            health.api === 'online'
              ? 'border-success/30 bg-success/10 text-success'
              : health.api === 'offline'
                ? 'border-critical/30 bg-critical/10 text-critical'
                : 'border-border bg-muted text-muted-foreground',
          )}
          title={
            health.lastCheck
              ? `Dernière vérification : ${new Date(health.lastCheck).toLocaleTimeString('fr-FR')}`
              : undefined
          }
        >
          <span
            className={cn(
              'h-1.5 w-1.5 rounded-full',
              health.api === 'online'
                ? 'bg-success animate-pulse'
                : health.api === 'offline'
                  ? 'bg-critical'
                  : 'bg-muted-foreground',
            )}
          />
          API {health.api === 'online' ? 'Online' : health.api === 'offline' ? 'Offline' : 'Unknown'}
        </span>

        <Button
          variant="ghost"
          size="icon"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          aria-label={theme === 'dark' ? 'Passer en mode clair' : 'Passer en mode sombre'}
          title={theme === 'dark' ? 'Mode clair' : 'Mode sombre'}
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>

        <Button asChild size="sm" className="gap-1.5">
          <Link to="/scan/new">
            <Plus className="h-4 w-4" /> <span className="hidden sm:inline">Nouveau scan</span>
          </Link>
        </Button>
      </div>
    </header>
  )
}
