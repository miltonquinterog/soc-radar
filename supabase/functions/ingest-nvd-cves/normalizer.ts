import type { NvdMetric, NvdPage, NvdRecord, NvdReference } from "./types.ts";

const CVE_ID = /^CVE-[0-9]{4}-[0-9]{4,}$/;
const GROUPS = [
  ["cvssMetricV2", "2.0"], ["cvssMetricV30", "3.0"],
  ["cvssMetricV31", "3.1"], ["cvssMetricV40", "4.0"],
] as const;

export function parseNvdPage(value: unknown): NvdPage {
  const page = object(value, "page");
  const totalResults = nonnegativeInteger(page.totalResults, "totalResults");
  const startIndex = nonnegativeInteger(page.startIndex, "startIndex");
  const resultsPerPage = nonnegativeInteger(page.resultsPerPage, "resultsPerPage");
  if (!Array.isArray(page.vulnerabilities) || resultsPerPage > 25 || page.vulnerabilities.length > 25) {
    throw new Error("invalid_nvd_page");
  }
  const records = page.vulnerabilities.map((item) => parseNvdRecord(object(item, "vulnerability").cve));
  return { totalResults, startIndex, resultsPerPage, records };
}

export function parseNvdRecord(value: unknown): NvdRecord {
  const raw = object(value, "cve");
  const cveId = requiredString(raw.id, "cve_id").toUpperCase();
  if (!CVE_ID.test(cveId)) throw new Error("invalid_cve_id");
  const sourceStatus = requiredString(raw.vulnStatus, "vuln_status");
  const publishedAt = isoDate(raw.published, "published");
  const modifiedAt = isoDate(raw.lastModified, "last_modified");
  const descriptions = Array.isArray(raw.descriptions) ? raw.descriptions : [];
  const english = descriptions.map((item) => object(item, "description"))
    .find((item) => item.lang === "en" && typeof item.value === "string" && item.value.trim());
  const description = english ? String(english.value).trim() : null;
  const rawMetrics = raw.metrics && typeof raw.metrics === "object" ? object(raw.metrics, "metrics") : {};
  const metrics: NvdMetric[] = [];
  const seenMetrics = new Map<string, string>();
  for (const [group, version] of GROUPS) {
    const candidates = rawMetrics[group];
    if (!Array.isArray(candidates)) continue;
    for (const candidate of candidates) {
      const metric = object(candidate, "metric");
      const data = object(metric.cvssData, "cvss_data");
      if (data.version !== undefined && data.version !== version) throw new Error("cvss_version_mismatch");
      const contributor = requiredString(metric.source, "metric_source");
      const metricType = metric.type === "Primary" ? "primary" : metric.type === "Secondary" ? "secondary" : "other";
      const baseScore = Number(data.baseScore);
      if (!Number.isFinite(baseScore) || baseScore < 0 || baseScore > 10) throw new Error("invalid_cvss_score");
      const vector = typeof data.vectorString === "string" ? data.vectorString : null;
      const normalized: NvdMetric = { version, metricType, contributor, baseScore, vector };
      const key = [version, metricType, contributor].join("|");
      const fingerprint = JSON.stringify(normalized);
      if (seenMetrics.has(key) && seenMetrics.get(key) !== fingerprint) throw new Error("conflicting_cvss_contribution");
      if (!seenMetrics.has(key)) metrics.push(normalized);
      seenMetrics.set(key, fingerprint);
    }
  }
  const references: NvdReference[] = [];
  const seenUrls = new Set<string>();
  for (const item of Array.isArray(raw.references) ? raw.references : []) {
    const reference = object(item, "reference");
    const url = requiredString(reference.url, "reference_url");
    const normalizedUrl = normalizeReferenceUrl(url);
    if (seenUrls.has(normalizedUrl)) continue;
    seenUrls.add(normalizedUrl);
    const tags = Array.isArray(reference.tags)
      ? [...new Set(reference.tags.filter((tag): tag is string => typeof tag === "string" && !!tag.trim()).map((tag) => tag.trim()))].sort()
      : [];
    references.push({ url, normalizedUrl, tags });
  }
  return {
    cveId, sourceStatus, status: mapNvdStatus(sourceStatus), publishedAt,
    modifiedAt, description, metrics, references,
  };
}

export function mapNvdStatus(value: string): NvdRecord["status"] {
  if (value === "Rejected") return "rejected";
  if (value === "Reserved") return "reserved";
  if (["Analyzed", "Modified", "Awaiting Analysis", "Undergoing Analysis", "Deferred"].includes(value)) return "published";
  return "unknown";
}

export function normalizeReferenceUrl(input: string): string {
  const url = new URL(input);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("invalid_reference_url");
  url.hash = "";
  url.hostname = url.hostname.toLowerCase();
  if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString();
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`invalid_${name}`);
  return value as Record<string, unknown>;
}
function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`invalid_${name}`);
  return value.trim();
}
function isoDate(value: unknown, name: string): string {
  const input = requiredString(value, name);
  const date = new Date(/[Zz]$|[+-]\d\d:\d\d$/.test(input) ? input : `${input}Z`);
  if (!Number.isFinite(date.getTime())) throw new Error(`invalid_${name}`);
  return date.toISOString();
}
function nonnegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new Error(`invalid_${name}`);
  return value as number;
}
