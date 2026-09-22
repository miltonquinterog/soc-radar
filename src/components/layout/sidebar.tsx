"use client";

import Link from "next/link";

const links = [["Dashboard", "/"], ["CVE", "/cves"], ["CISA KEV", "/kev"], ["Advisories", "/advisories"], ["Noticias", "/news"], ["Fabricantes", "/vendors"], ["Buscar", "/search"], ["Acerca de", "/about"]];

type SidebarProps = { collapsed: boolean; onToggle: () => void };

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const toggleLabel = collapsed ? "Expandir navegación" : "Contraer navegación";
  return <aside className="side">
    <button aria-expanded={!collapsed} aria-label={toggleLabel} className="sidebar-toggle" onClick={onToggle} title={toggleLabel} type="button"><span aria-hidden>{collapsed ? "›" : "‹"}</span></button>
    <div className="brand"><span className="brand-initials" aria-hidden="true">SR</span><div className="brand-copy">SOC Radar<small>Threat intelligence</small></div></div>
    <nav aria-label="Navegación principal"><div className="label">Operación</div>{links.map(([name, path]) => <Link aria-label={name} className="nav" href={path} key={path} title={collapsed ? name : undefined}><span className="nav-icon" aria-hidden>◌</span><span className="nav-label">{name}</span></Link>)}</nav>
    <div className="side-footer"><span className="platform-mark">SOC RADAR</span><small>Security operations</small></div>
  </aside>;
}
