import type { SupabaseClient } from "npm:@supabase/supabase-js@2";
import { canonicalPatch, choosePrimaryMetric } from "./policy.ts";
import type { CollectorMode, NvdMetric, NvdRecord, PageClaim, PageCounters, RecordOutcome } from "./types.ts";

type CveRow = {
  id: string; status: string; description: string | null; description_source_id: string | null;
  published_at: string | null; last_modified_at: string | null;
};
type MetricRow = {
  id: string; source_id: string; version: string; metric_type: string;
  metric_source_identifier: string; base_score: number; vector: string | null; is_primary: boolean;
};

export class RepositoryError extends Error {
  readonly stage: string;
  constructor(stage: string) {
    super(stage);
    this.stage = stage;
    this.name = "RepositoryError";
  }
}

export class NvdRepository {
  private readonly db: SupabaseClient;
  constructor(db: SupabaseClient) { this.db = db; }

  async ensureSource(): Promise<string> {
    const { data, error } = await this.db.from("sources").upsert({
      source_key: "nvd", name: "NIST National Vulnerability Database",
      source_type: "vulnerability_database", base_url: "https://nvd.nist.gov/",
    }, { onConflict: "source_key" }).select("id").single();
    check(error, "source_upsert");
    if (!data) throw new RepositoryError("source_upsert");
    return data.id as string;
  }

  async claim(sourceId: string, mode: CollectorMode, start: string | null, end: string | null): Promise<PageClaim | null> {
    const { data, error } = await this.db.rpc("claim_nvd_page", {
      p_source_id: sourceId, p_mode: mode, p_window_start: start, p_window_end: end,
    });
    check(error, "page_claim");
    return ((data as PageClaim[] | null) ?? [])[0] ?? null;
  }

  async complete(claim: PageClaim, totalResults: number, pageCount: number, counts: PageCounters) {
    const { data, error } = await this.db.rpc("complete_nvd_page", {
      p_state_id: claim.state_id, p_run_id: claim.run_id, p_lease_token: claim.lease_token,
      p_total_results: totalResults, p_page_count: pageCount,
      p_inserted: counts.inserted, p_updated: counts.updated, p_skipped: counts.skipped,
    });
    check(error, "page_complete");
    return ((data as Array<{ status: string; next_start_index: number }> | null) ?? [])[0] ?? null;
  }

  async fail(claim: PageClaim, code: "fetch_failed" | "invalid_response" | "record_failed" | "checkpoint_failed", errors: Array<Record<string, string>>, errorCount = errors.length) {
    const { error } = await this.db.rpc("fail_nvd_page", {
      p_state_id: claim.state_id, p_run_id: claim.run_id, p_lease_token: claim.lease_token,
      p_error_code: code, p_error_count: Math.max(1, Math.min(25, errorCount)),
      p_first_errors: errors.slice(0, 20),
    });
    check(error, "page_fail");
  }

  async processRecord(sourceId: string, record: NvdRecord): Promise<RecordOutcome> {
    const { cve, created, canonicalChanged } = await this.ensureCve(sourceId, record);
    const sourceChanged = await this.observeSource(cve.id, sourceId, record);
    const metricsChanged = await this.persistMetrics(cve.id, sourceId, record);
    const referencesChanged = await this.persistReferences(cve.id, sourceId, record);
    return created ? "inserted" : canonicalChanged || sourceChanged || metricsChanged || referencesChanged ? "updated" : "skipped";
  }

  private async ensureCve(sourceId: string, record: NvdRecord): Promise<{ cve: CveRow; created: boolean; canonicalChanged: boolean }> {
    const { data, error } = await this.db.from("cves").select("id,status,description,description_source_id,published_at,last_modified_at")
      .eq("cve_id", record.cveId).maybeSingle();
    check(error, "cve_lookup");
    let existing = data as CveRow | null;
    if (!existing) {
      const { data: inserted, error: insertError } = await this.db.from("cves").insert({
        cve_id: record.cveId, status: record.status,
        description: record.description, description_source_id: record.description ? sourceId : null,
        published_at: record.publishedAt,
        last_modified_at: new Date(Math.max(Date.parse(record.publishedAt), Date.parse(record.modifiedAt))).toISOString(),
      }).select("id,status,description,description_source_id,published_at,last_modified_at").single();
      if (!insertError && inserted) return { cve: inserted as CveRow, created: true, canonicalChanged: false };
      if (insertError?.code !== "23505") throw new RepositoryError("cve_insert");
      const retry = await this.db.from("cves").select("id,status,description,description_source_id,published_at,last_modified_at")
        .eq("cve_id", record.cveId).single();
      check(retry.error, "cve_race_lookup");
      existing = retry.data as CveRow;
    }
    const patch = canonicalPatch(existing, record, sourceId);
    if (Object.keys(patch).length) {
      const { error: updateError } = await this.db.from("cves").update(patch).eq("id", existing.id);
      check(updateError, "cve_update");
    }
    return { cve: existing, created: false, canonicalChanged: Object.keys(patch).length > 0 };
  }

  private async observeSource(cveId: string, sourceId: string, record: NvdRecord) {
    const { data, error } = await this.db.from("cve_sources")
      .select("source_record_id,source_url,source_published_at,source_updated_at,source_status")
      .eq("cve_id", cveId).eq("source_id", sourceId).maybeSingle();
    check(error, "cve_source_lookup");
    const sourceUrl = `https://nvd.nist.gov/vuln/detail/${record.cveId}`;
    const changed = !data || data.source_record_id !== record.cveId ||
      data.source_url !== sourceUrl || !sameTime(data.source_published_at, record.publishedAt) ||
      !sameTime(data.source_updated_at, record.modifiedAt) || data.source_status !== record.sourceStatus;
    const observed = await this.db.rpc("observe_nvd_cve_source", {
      p_cve_id: cveId, p_source_id: sourceId, p_source_record_id: record.cveId,
      p_source_url: sourceUrl, p_source_published_at: record.publishedAt,
      p_source_updated_at: record.modifiedAt, p_source_status: record.sourceStatus,
    });
    check(observed.error, "cve_source_observe");
    return changed;
  }

  private async persistMetrics(cveId: string, sourceId: string, record: NvdRecord) {
    const { data, error } = await this.db.from("cve_cvss_metrics")
      .select("id,source_id,version,metric_type,metric_source_identifier,base_score,vector,is_primary")
      .eq("cve_id", cveId);
    check(error, "metric_lookup");
    const rows = (data ?? []) as MetricRow[];
    let changed = false;
    for (const metric of record.metrics) {
      const existing = rows.find((row) => row.source_id === sourceId && keyOf(row) === keyOf(metric));
      if (!existing) {
        const { data: inserted, error: insertError } = await this.db.from("cve_cvss_metrics").insert({
          cve_id: cveId, source_id: sourceId, version: metric.version,
          metric_type: metric.metricType, metric_source_identifier: metric.contributor,
          base_score: metric.baseScore, vector: metric.vector,
          source_updated_at: record.modifiedAt, is_primary: false,
        }).select("id,source_id,version,metric_type,metric_source_identifier,base_score,vector,is_primary").single();
        check(insertError, "metric_insert");
        if (!inserted) throw new RepositoryError("metric_insert");
        rows.push(inserted as MetricRow);
        changed = true;
      } else if (Number(existing.base_score) !== metric.baseScore || existing.vector !== metric.vector) {
        const { error: updateError } = await this.db.from("cve_cvss_metrics").update({
          base_score: metric.baseScore, vector: metric.vector, source_updated_at: record.modifiedAt,
        }).eq("id", existing.id);
        check(updateError, "metric_update");
        changed = true;
      }
    }
    if (rows.some((row) => row.is_primary && row.source_id !== sourceId)) return changed;
    const winner = choosePrimaryMetric(record.metrics);
    const chosen = winner && rows.find((row) => row.source_id === sourceId && keyOf(row) === keyOf(winner));
    if (!chosen) return changed;
    if (rows.find((row) => row.is_primary)?.id !== chosen.id) {
      const { error: demoteError } = await this.db.from("cve_cvss_metrics").update({ is_primary: false })
        .eq("cve_id", cveId).eq("source_id", sourceId).eq("is_primary", true);
      check(demoteError, "metric_demote");
      const { error: promoteError } = await this.db.from("cve_cvss_metrics").update({ is_primary: true }).eq("id", chosen.id);
      check(promoteError, "metric_promote");
      changed = true;
    }
    return changed;
  }

  private async persistReferences(cveId: string, sourceId: string, record: NvdRecord) {
    let changed = false;
    for (const reference of record.references) {
      const { data, error } = await this.db.from("cve_references").select("id")
        .eq("cve_id", cveId).eq("normalized_url", reference.normalizedUrl).maybeSingle();
      check(error, "reference_lookup");
      if (data) continue; // Existing provenance, including another source, is retained.
      const { error: insertError } = await this.db.from("cve_references").insert({
        cve_id: cveId, source_id: sourceId, url: reference.url,
        normalized_url: reference.normalizedUrl,
        reference_type: reference.tags.length ? reference.tags.join(", ").slice(0, 500) : null,
      });
      if (insertError?.code === "23505") continue;
      check(insertError, "reference_insert");
      changed = true;
    }
    return changed;
  }
}

function keyOf(value: MetricRow | NvdMetric) {
  return "metric_source_identifier" in value
    ? [value.version, value.metric_type, value.metric_source_identifier].join("|")
    : [value.version, value.metricType, value.contributor].join("|");
}
function sameTime(a: string | null, b: string) {
  return !!a && Date.parse(a) === Date.parse(b);
}
function check(error: { code?: string; message: string } | null, stage: string) {
  if (error) throw new RepositoryError(stage);
}
