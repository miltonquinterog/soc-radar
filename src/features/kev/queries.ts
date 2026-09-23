import { createClient } from "@/lib/supabase/server";
import type { KevDashboardData, KevEntry, KevOverview, KevProduct, KevVendor } from "./types";

function readOverview(data: unknown): KevOverview {
  const row = Array.isArray(data) ? data[0] : null;
  if (!row || typeof row.total_kev !== "number" || typeof row.added_last_7_days !== "number") {
    throw new Error("La respuesta del resumen CISA KEV no es válida.");
  }
  return row as KevOverview;
}

function readRows<T>(data: unknown): T[] {
  if (!Array.isArray(data)) throw new Error("La respuesta de CISA KEV no es válida.");
  return data as T[];
}

export async function getPublicKevDashboardData(): Promise<KevDashboardData> {
  const db = await createClient();
  const [overview, entries, vendors, products] = await Promise.all([
    db.rpc("get_public_kev_dashboard"),
    db.rpc("get_public_kev_entries", { p_limit: 8, p_offset: 0 }),
    db.rpc("get_public_kev_vendors", { p_limit: 5 }),
    db.rpc("get_public_kev_products", { p_limit: 5 }),
  ]);
  if (overview.error || entries.error || vendors.error || products.error) {
    throw new Error("No se pudieron consultar los datos públicos de CISA KEV.");
  }
  return {
    overview: readOverview(overview.data),
    entries: readRows<KevEntry>(entries.data),
    vendors: readRows<KevVendor>(vendors.data),
    products: readRows<KevProduct>(products.data),
    loadedAt: new Date().toISOString(),
  };
}

export async function getPublicKevPageData(page: number): Promise<{
  overview: KevOverview;
  entries: KevEntry[];
}> {
  if (!Number.isSafeInteger(page) || page < 1) throw new Error("Página KEV no válida.");
  const db = await createClient();
  const [overview, entries] = await Promise.all([
    db.rpc("get_public_kev_dashboard"),
    db.rpc("get_public_kev_entries", { p_limit: 25, p_offset: (page - 1) * 25 }),
  ]);
  if (overview.error || entries.error) {
    throw new Error("No se pudo consultar el catálogo público CISA KEV.");
  }
  return { overview: readOverview(overview.data), entries: readRows<KevEntry>(entries.data) };
}
