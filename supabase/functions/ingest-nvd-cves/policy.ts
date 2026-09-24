import type { NvdMetric } from "./types.ts";

const VERSION_RANK: Record<NvdMetric["version"], number> = {
  "2.0": 2, "3.0": 30, "3.1": 31, "4.0": 40,
};

/**
 * Operational CVSS selection: Primary before Secondary/Other, then newest
 * version, then NVD's own contribution, then stable contributor/vector order.
 * `metricType=primary` is source metadata; only the winner gets is_primary=true.
 */
export function choosePrimaryMetric(metrics: NvdMetric[]): NvdMetric | null {
  return [...metrics].sort((a, b) =>
    typeRank(a.metricType) - typeRank(b.metricType) ||
    VERSION_RANK[b.version] - VERSION_RANK[a.version] ||
    contributorRank(a.contributor) - contributorRank(b.contributor) ||
    a.contributor.localeCompare(b.contributor) ||
    (a.vector ?? "").localeCompare(b.vector ?? ""),
  )[0] ?? null;
}

function typeRank(type: NvdMetric["metricType"]) {
  return type === "primary" ? 0 : type === "secondary" ? 1 : 2;
}

function contributorRank(value: string) {
  return value.toLowerCase() === "nvd@nist.gov" ? 0 : 1;
}

export function canonicalPatch(existing: {
  status: string;
  description: string | null;
  description_source_id: string | null;
  published_at: string | null;
  last_modified_at: string | null;
}, incoming: {
  status: string;
  description: string | null;
  publishedAt: string;
  modifiedAt: string;
}, nvdSourceId: string): Record<string, string> {
  const patch: Record<string, string> = {};
  if (incoming.description &&
    (!existing.description || existing.description_source_id === nvdSourceId) &&
    existing.description !== incoming.description) {
    patch.description = incoming.description;
    patch.description_source_id = nvdSourceId;
  }
  if (!existing.published_at) patch.published_at = incoming.publishedAt;
  const effectivePublished = existing.published_at ?? incoming.publishedAt;
  const latest = Math.max(
    Date.parse(existing.last_modified_at ?? "1970-01-01T00:00:00Z"),
    Date.parse(incoming.modifiedAt), Date.parse(effectivePublished),
  );
  if (!existing.last_modified_at || latest > Date.parse(existing.last_modified_at)) {
    patch.last_modified_at = new Date(latest).toISOString();
  }
  if (incoming.status === "rejected" && existing.status !== "rejected") patch.status = "rejected";
  else if (incoming.status === "published" && ["unknown", "reserved"].includes(existing.status)) patch.status = "published";
  else if (incoming.status === "reserved" && existing.status === "unknown") patch.status = "reserved";
  return patch;
}
