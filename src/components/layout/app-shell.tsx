"use client";

import { useState, type ReactNode } from "react";
import { AppHeader } from "@/components/layout/app-header";
import { Sidebar } from "@/components/layout/sidebar";

export function AppShell({ children }: { children: ReactNode }) {
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);

  return (
    <div className={`app${isSidebarCollapsed ? " is-sidebar-collapsed" : ""}`}>
      <Sidebar collapsed={isSidebarCollapsed} onToggle={() => setIsSidebarCollapsed((current) => !current)} />
      <main><AppHeader /><div className="content">{children}</div></main>
    </div>
  );
}
