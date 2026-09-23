export const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";

export type CisaKevRecord = {
  cveID?: unknown;
  vendorProject?: unknown;
  product?: unknown;
  vulnerabilityName?: unknown;
  dateAdded?: unknown;
  shortDescription?: unknown;
  requiredAction?: unknown;
  dueDate?: unknown;
  knownRansomwareCampaignUse?: unknown;
  forensicTriage?: unknown;
  notes?: unknown;
  cwes?: unknown;
};

export type CisaCatalog = {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevRecord[];
};

export type NormalizedKevRecord = {
  cveId: string;
  vendorName: string;
  vendorSlug: string;
  productName: string;
  productSlug: string;
  vulnerabilityName: string | null;
  dateAdded: string;
  dueDate: string | null;
  shortDescription: string | null;
  requiredAction: string;
  knownRansomwareCampaignUse: boolean | null;
  notes: string | null;
};

export type RunCounters = {
  records_found: number;
  records_inserted: number;
  records_updated: number;
  records_skipped: number;
  error_count: number;
};

export type IngestionRun = {
  id: string;
  source_payload_hash: string | null;
  batch_size: number;
  batches_total: number;
  batches_completed: number;
  next_batch_number: number;
  active_batch_number: number | null;
  active_batch_claimed_at: string | null;
};

export type IngestionBatchClaim = {
  batch_number: number;
  lease_token: string;
  batch_size: number;
  batches_total: number;
  batches_completed: number;
};

export type IngestionBatchCompletion = {
  status: "running" | "succeeded" | "partial" | "failed";
  batches_completed: number;
  batches_total: number;
  next_batch_number: number;
  records_inserted: number;
  records_updated: number;
  records_skipped: number;
  error_count: number;
};

export type RecordOutcome = "inserted" | "updated" | "skipped";

export class CatalogValidationError extends Error {}
export class RecordValidationError extends Error {}