import Link from "next/link";
import { PriorityTable } from "@/components/dashboard/priority-table";
import { getPublicKevPageData } from "@/features/kev/queries";

const PAGE_SIZE = 25;

export default async function Page({ searchParams }: { searchParams: Promise<{ page?: string | string[] }> }) {
  const params = await searchParams;
  const rawPage = Array.isArray(params.page) ? params.page[0] : params.page;
  const parsedPage = rawPage && /^\d+$/.test(rawPage) ? Number(rawPage) : 1;
  const page = Number.isSafeInteger(parsedPage) && parsedPage >= 1 && parsedPage <= 100000 ? parsedPage : 1;
  const { overview, entries } = await getPublicKevPageData(page);
  const totalPages = Math.max(1, Math.ceil(overview.total_kev / PAGE_SIZE));

  return <>
    <p className="eyebrow">CISA KEV · DATOS REALES</p>
    <h1>Vulnerabilidades con explotación conocida</h1>
    <p className="subtitle">Catálogo público de CISA. No se muestran puntuaciones CVSS ni severidades no verificadas.</p>
    <div className="kev-overview"><strong>{overview.total_kev.toLocaleString("es-CO")}</strong> entradas · <strong>{overview.added_last_7_days}</strong> añadidas en los últimos 7 días calendario · <strong>{overview.known_ransomware_count}</strong> con uso conocido en campañas de ransomware</div>
    <section className="panel priority-panel">
      <div className="panel-head"><div><h2>Entradas CISA KEV <span className="data-source data-source-cisa">CISA KEV · REAL</span></h2><p>Ordenadas por fecha de incorporación y CVE</p></div></div>
      <div className="panel-body">{entries.length ? <PriorityTable entries={entries} /> : <p className="kev-state">No hay entradas para esta página.</p>}</div>
    </section>
    <nav className="kev-pagination" aria-label="Paginación de CISA KEV">
      {page > 1 && <Link href={`/kev?page=${page - 1}`}>← Anterior</Link>}
      <span>Página {page} de {totalPages}</span>
      {page < totalPages && <Link href={`/kev?page=${page + 1}`}>Siguiente →</Link>}
    </nav>
  </>;
}
