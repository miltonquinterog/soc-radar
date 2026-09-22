import Link from "next/link";
import { AdvisoryCard } from "@/components/advisories/advisory-card";
import { AutoRefreshStatus } from "@/components/dashboard/auto-refresh-status";
import { PriorityTable } from "@/components/dashboard/priority-table";
import { SeverityDonut, TrendChart } from "@/components/dashboard/security-charts";
import { NewsCard } from "@/components/news/news-card";
import { StatCard } from "@/components/ui/security-badges";
import { advisories, cves, news, vendors } from "@/lib/constants/mock-data";

function Panel({
  title,
  subtitle,
  href,
  className = "",
  children,
}: {
  title: string;
  subtitle: string;
  href: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <div><h2>{title}</h2><p>{subtitle}</p></div>
        <Link className="panel-action" href={href}>Ver todos <span aria-hidden="true">→</span></Link>
      </div>
      <div className="panel-body">{children}</div>
    </section>
  );
}

const mostActiveVendors = vendors.slice(0, 5);
const highestActivity = mostActiveVendors[0]?.advisories ?? 1;

export function Dashboard() {
  return (
    <>
      <section className="dashboard-toolbar">
        <div>
          <p className="eyebrow">Vista operativa</p>
          <h1>Dashboard de seguridad</h1>
          <p className="subtitle">Vulnerabilidades, KEV y publicaciones recientes para priorización SOC.</p>
        </div>
        <div className="time-controls" aria-label="Ventana de demostración: siete días">
          <span className="live-dot">Demo</span>
          <span className="time-option">24 h</span>
          <span className="time-option selected">7 días</span>
          <span className="time-option">30 días</span>
        </div>
      </section>
      <AutoRefreshStatus />
      <section className="metric-section">
        <div className="metric-label">Exposición y priorización</div>
        <div className="stats">
          <StatCard label="CVE críticos" value="12" detail="3 publicados hoy" tone="critical" />
          <StatCard label="CVE alta severidad" value="38" detail="8 desde ayer" tone="high" />
          <StatCard label="Añadidos recientemente" value="24" detail="CVE en las últimas 24 h" tone="medium" />
          <StatCard label="En CISA KEV" value="6" detail="2 con explotación activa" tone="kev" />
        </div>
      </section>
      <Panel title="Prioridad SOC" subtitle="CVE que requieren evaluación o remediación" href="/cves" className="priority-panel">
        <PriorityTable cves={cves} />
      </Panel>
      <div className="analytics-grid">
        <Panel title="Actividad de vulnerabilidades" subtitle="CVE añadidos por día y severidad" href="/cves">
          <TrendChart />
        </Panel>
        <Panel title="Distribución por severidad" subtitle="CVE añadidos en los últimos siete días" href="/cves">
          <SeverityDonut />
        </Panel>
      </div>
      <div className="columns dashboard-lower-grid">
        <div className="stack">
          <Panel title="Advisories recientes" subtitle="Publicaciones de fabricantes" href="/advisories">
            {advisories.map((item) => <AdvisoryCard key={item.id} advisory={item} />)}
          </Panel>
          <Panel title="Noticias recientes" subtitle="Contexto para el equipo de defensa" href="/news">
            {news.map((item) => <NewsCard key={item.id} item={item} />)}
          </Panel>
        </div>
        <Panel title="Actividad de fabricantes" subtitle="Advisories publicados en el período" href="/vendors">
          <ol className="vendor-activity">
            {mostActiveVendors.map((item) => (
              <li key={item.name}>
                <div className="vendor-activity-heading">
                  <span className="title">{item.name}</span>
                  <strong>{item.advisories} advisories</strong>
                </div>
                <div className="vendor-activity-track" aria-hidden="true">
                  <span style={{ width: `${(item.advisories / highestActivity) * 100}%` }} />
                </div>
                <span className="meta">Última publicación: {item.latest}</span>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </>
  );
}
