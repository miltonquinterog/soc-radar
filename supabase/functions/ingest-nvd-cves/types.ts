export type CollectorMode = "bootstrap" | "incremental";
export type RecordOutcome = "inserted" | "updated" | "skipped";

export type NvdMetric = {
  version: "2.0" | "3.0" | "3.1" | "4.0";
  metricType: "primary" | "secondary" | "other";
  contributor: string;
  baseScore: number;
  vector: string | null;
};

export type NvdReference = {
  url: string;
  normalizedUrl: string;
  tags: string[];
};

export type NvdRecord = {
  cveId: string;
  sourceStatus: string;
  status: "unknown" | "reserved" | "published" | "rejected";
  publishedAt: string;
  modifiedAt: string;
  description: string | null;
  metrics: NvdMetric[];
  references: NvdReference[];
};

export type NvdPage = {
  totalResults: number;
  startIndex: number;
  resultsPerPage: number;
  records: NvdRecord[];
};

export type PageClaim = {
  state_id: string;
  run_id: string;
  lease_token: string;
  window_start: string;
  window_end: string;
  start_index: number;
  page_size: number;
};

export type PageCounters = {
  inserted: number;
  updated: number;
  skipped: number;
};
