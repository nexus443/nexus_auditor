import { SidebarNav } from './SidebarNav'

export function Sidebar() {
  return (
    <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-border bg-sidebar/80 backdrop-blur-xl">
      <SidebarNav />
    </aside>
  )
}
