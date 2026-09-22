import Link from "next/link";
import { CvssScore, KevBadge, SeverityBadge } from "@/components/ui/security-badges";
import type { Cve } from "@/types/security";

export function PriorityTable({ cves }: { cves: Cve[] }) {
  return (
    <div className="priority-table-scroll" role="region" aria-label="Tabla de prioridad SOC" tabIndex={0}>
      <table className="priority-table">
        <caption className="sr-only">CVE priorizados para evaluación por el SOC</caption>
        <thead>
          <tr>
            <th scope="col">CVE ID</th>
            <th scope="col">Fabricante</th>
            <th scope="col">Producto</th>
            <th scope="col">CVSS</th>
            <th scope="col">Severidad</th>
            <th scope="col">CISA KEV</th>
            <th scope="col">Publicado</th>
            <th scope="col">Acción</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((cve) => (
            <tr key={cve.id}>
              <th scope="row">{cve.id}</th>
              <td>{cve.vendor}</td>
              <td>{cve.product}</td>
              <td><CvssScore score={cve.score} severity={cve.severity} /></td>
              <td><SeverityBadge severity={cve.severity} /></td>
              <td>{cve.kev ? <KevBadge /> : <span className="meta">No</span>}</td>
              <td className="priority-date">{cve.published}</td>
              <td><Link className="priority-link" href={`/cves#${cve.id}`} aria-label={`Ver detalle de ${cve.id}`}>Ver detalle <span aria-hidden="true">→</span></Link></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
