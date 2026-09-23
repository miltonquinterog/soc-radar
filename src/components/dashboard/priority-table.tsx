import { formatKevDate, formatRansomwareUse } from "@/features/kev/format";
import type { KevEntry } from "@/features/kev/types";

export function PriorityTable({ entries }: { entries: KevEntry[] }) {
  return (
    <div className="priority-table-scroll" role="region" aria-label="Tabla de prioridad SOC" tabIndex={0}>
      <table className="priority-table">
        <caption className="sr-only">Entradas CISA KEV para evaluación por el SOC, ordenadas por fecha de incorporación</caption>
        <thead>
          <tr>
            <th scope="col">CVE</th>
            <th scope="col">Fabricante</th>
            <th scope="col">Producto</th>
            <th scope="col">Añadida a KEV</th>
            <th scope="col">Fecha límite CISA</th>
            <th scope="col">Ransomware conocido</th>
            <th scope="col">Acción requerida por CISA</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.cve_id} id={entry.cve_id}>
              <th scope="row">
                {entry.cve_id}
                {entry.source_vulnerability_name && <span className="priority-vulnerability">{entry.source_vulnerability_name}</span>}
              </th>
              <td>{entry.source_vendor_name ?? "No indicado"}</td>
              <td>{entry.source_product_name ?? "No indicado"}</td>
              <td className="priority-date">{formatKevDate(entry.date_added)}</td>
              <td className="priority-date">{formatKevDate(entry.due_date)}</td>
              <td>{formatRansomwareUse(entry.known_ransomware_campaign_use)}</td>
              <td className="priority-action">{entry.required_action}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
