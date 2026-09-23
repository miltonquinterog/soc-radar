import { CISA_KEV_URL, CatalogValidationError, type CisaCatalog } from "./types.ts";

const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 20_000;

export async function fetchCisaKevCatalog() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(CISA_KEV_URL, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });

    if (!response.ok) throw new CatalogValidationError("catalog_http_error");
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("json")) throw new CatalogValidationError("catalog_content_type_invalid");
    const contentLength = Number(response.headers.get("content-length") ?? 0);
    if (contentLength > MAX_PAYLOAD_BYTES) throw new CatalogValidationError("catalog_payload_too_large");

    const payload = await response.text();
    if (!payload.trim() || new TextEncoder().encode(payload).byteLength > MAX_PAYLOAD_BYTES) {
      throw new CatalogValidationError("catalog_payload_empty_or_too_large");
    }

    return { catalog: parseCisaKevCatalog(payload), payloadHash: await sha256(payload), payloadBytes: new TextEncoder().encode(payload).byteLength };
  } catch (error) {
    if (error instanceof CatalogValidationError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") throw new CatalogValidationError("catalog_timeout");
    throw new CatalogValidationError("catalog_fetch_failed");
  } finally {
    clearTimeout(timeout);
  }
}

export function parseCisaKevCatalog(payload: string): CisaCatalog {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    throw new CatalogValidationError("catalog_json_invalid");
  }

  if (!parsed || typeof parsed !== "object") throw new CatalogValidationError("catalog_shape_invalid");
  const catalog = parsed as Partial<CisaCatalog>;
  if (typeof catalog.catalogVersion !== "string" || !catalog.catalogVersion.trim()) throw new CatalogValidationError("catalog_version_invalid");
  if (typeof catalog.dateReleased !== "string" || Number.isNaN(Date.parse(catalog.dateReleased))) throw new CatalogValidationError("catalog_release_date_invalid");
  if (!Number.isInteger(catalog.count) || (catalog.count ?? -1) < 0) throw new CatalogValidationError("catalog_count_invalid");
  if (!Array.isArray(catalog.vulnerabilities) || catalog.vulnerabilities.length === 0) throw new CatalogValidationError("catalog_vulnerabilities_empty");
  if (catalog.count !== catalog.vulnerabilities.length) throw new CatalogValidationError("catalog_count_inconsistent");

  return {
    title: typeof catalog.title === "string" ? catalog.title : "CISA Known Exploited Vulnerabilities Catalog",
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased,
    count: catalog.count,
    vulnerabilities: catalog.vulnerabilities,
  };
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
