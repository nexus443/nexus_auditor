import { Navigate, Route, Routes } from 'react-router-dom'

import { AppShell } from '@/components/layout/AppShell'
import { NexusProvider } from '@/hooks/useNexus.jsx'
import Dashboard from '@/pages/Dashboard.jsx'
import NewScan from '@/pages/NewScan.jsx'
import LiveScan from '@/pages/LiveScan.jsx'
import Results from '@/pages/Results.jsx'
import History from '@/pages/History.jsx'
import Reports from '@/pages/Reports.jsx'
import Settings from '@/pages/Settings.jsx'
import NotFound from '@/pages/NotFound.jsx'

/**
 * Routage de l'application.
 *
 * L'ensemble de l'état fonctionnel (scan courant, historique, santé de l'API,
 * préférences) est fourni par `NexusProvider`, qui reprend la logique
 * auparavant contenue dans l'unique composant `App`.
 */
export default function App() {
  return (
    <NexusProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Dashboard />} />
          <Route path="scan/new" element={<NewScan />} />
          <Route path="scan/live" element={<LiveScan />} />
          <Route path="scan" element={<Navigate to="/scan/new" replace />} />
          <Route path="results" element={<Results />} />
          <Route path="history" element={<History />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </NexusProvider>
  )
}
