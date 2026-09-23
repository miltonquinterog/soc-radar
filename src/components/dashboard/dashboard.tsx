import Link from "next/link";
import { AdvisoryCard } from "@/components/advisories/advisory-card";
import { AutoRefreshStatus } from "@/components/dashboard/auto-refresh-status";
import { PriorityTable } from "@/components/dashboard/priority-table";
import { SeverityDonut, TrendChart } from "@/components/dashboard/security-charts";
import { NewsCard } from "@/components/news/news-card";
import { StatCard } from "@/components/ui/security-badges";
import type { KevDashboardData } from "@/features/kev/types";
import { advisories, news } from "@/lib/constants/mock-data";

function Panel({ title, subtitle, href, source, className = "", children }: {
  title: string; subtitle: string; href: string; source: "demo" | "cisa";
  className?: string; children: React.ReactNode;
}) {
  return <section className={`panel ${className}`}>
    <div className="panel-head">
      <div><h2>{title} <span className={`data-source data-source-${source}`}>{source === "cisa" ? "CISA KEV · REAL" : "DEMO"}</span></h2><p>{subtitle}</p></div>
      <Link className="panel-action" href={href}>Ver todos <span aria-hidden="true">→</span></Link>
    </div>
    <div className="panel-body">{children}</div>
  </section>;
}

export function Dashboard({ kev, kevError = false }: { kev: KevDashboardData | null; kevError?: boolean }) {
  const vendors = kev?.vendors ?? [];
  const highestActivity = vendors[0]?.kev_count ?? 1;
  return <>
    <section className="dashboard-toolbar">
      <div>
        <p className="eyebrow">Vista operativa</p>
        <h1>Dashboard de seguridad</h1>
        <p className="subtitle">CISA KEV en tiempo de consulta; el resto de las fuentes permanece en demostración.</p>
      </div>
      <div className="time-controls"><span className="live-dot">CISA KEV real · otras secciones demo</span></div>
    </section>
    <AutoRefreshStatus loadedAt={kev?.loadedAt} />
    <section className="metric-section">
      <div className="metric-label">Exposición y priorización</div>
      <div className="stats">
        <StatCard label="CVE críticos" value="12" detail="Dato de demostración" tone="critical" source="demo" />
        <StatCard label="CVE alta severidad" value="38" detail="Dato de demostración" tone="high" source="demo" />
        <StatCard label="Añadidos recientemente" value={kev ? String(kev.overview.added_last_7_days) : "—"} detail="CISA KEV · últimos 7 días calendario" tone="medium" source="cisa" />
        <StatCard label="En CISA KEV" value={kev ? kev.overview.total_kev.toLocaleString("es-CO") : "—"} detail="Total de entradas en el catálogo" tone="kev" source="cisa" />
      </div>
    </section>
    <Panel title="Prioridad SOC" subtitle="Entradas CISA KEV más recientes para evaluación o remediación" href="/kev" source="cisa" className="priority-panel">
      {kevError ? <p className="kev-state" role="alert">No se pudieron cargar los datos CISA KEV. Intenta actualizar la página.</p> :
        kev?.entries.length ? <PriorityTable entries={kev.entries} /> : <p className="kev-state">No hay entradas CISA KEV disponibles.</p>}
    </Panel>
    <div className="analytics-grid">
      <Panel title="Actividad de vulnerabilidades" subtitle="CVE añadidos por día y severidad · datos de ejemplo" href="/cves" source="demo"><TrendChart /></Panel>
      <Panel title="Distribución por severidad" subtitle="CVE añadidos en los últimos siete días · datos de ejemplo" href="/cves" source="demo"><SeverityDonut /></Panel>
    </div>
    <div className="columns dashboard-lower-grid">
      <div className="stack">
        <Panel title="Advisories recientes" subtitle="Publicaciones de ejemplo de fabricantes" href="/advisories" source="demo">
          {advisories.map((item) => <AdvisoryCard key={item.id} advisory={item} />)}
        </Panel>
        <Panel title="Noticias recientes" subtitle="Noticias de ejemplo para el equipo de defensa" href="/news" source="demo">
          {news.map((item) => <NewsCard key={item.id} item={item} />)}
        </Panel>
      </div>
      <div className="stack">
        <Panel title="Fabricantes en CISA KEV" subtitle="Mayor número de entradas en el catálogo CISA" href="/kev" source="cisa">
          {kevError ? <p className="kev-state">No se pudieron cargar los fabricantes.</p> : vendors.length ?
            <ol className="vendor-activity">{vendors.map((item) => <li key={item.vendor_name}>
              <div className="vendor-activity-heading"><span className="title">{item.vendor_name}</span><strong>{item.kev_count} KEV</strong></div>
              <div className="vendor-activity-track" aria-hidden="true"><span style={{ width: `${(item.kev_count / highestActivity) * 100}%` }} /></div>
            </li>)}</ol> : <p className="kev-state">No hay fabricantes disponibles.</p>}
        </Panel>
        <Panel title="Productos en CISA KEV" subtitle="Productos con más entradas KEV" href="/kev" source="cisa">
          {kevError ? <p className="kev-state">No se pudieron cargar los productos.</p> : kev?.products.length ?
            <ol className="vendor-activity">{kev.products.map((item) => <li key={`${item.vendor_name}-${item.product_name}`}>
              <div className="vendor-activity-heading"><span className="title">{item.vendor_name} · {item.product_name}</span><strong>{item.kev_count} KEV</strong></div>
            </li>)}</ol> : <p className="kev-state">No hay productos disponibles.</p>}
        </Panel>
        <Panel title="Ransomware conocido" subtitle="Indicador informado por el catálogo CISA KEV" href="/kev" source="cisa">
          {kevError ? <p className="kev-state">No se pudo cargar el indicador.</p> : kev && <p className="kev-summary"><strong>{kev.overview.known_ransomware_count.toLocaleString("es-CO")}</strong> con uso conocido · <strong>{kev.overview.unknown_ransomware_count.toLocaleString("es-CO")}</strong> sin indicación. «Sin indicación» no equivale a ausencia de uso.</p>}
        </Panel>
      </div>
    </div>
  </>;
}
