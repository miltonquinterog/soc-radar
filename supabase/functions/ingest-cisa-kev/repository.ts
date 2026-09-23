import type { SupabaseClient } from "npm:@supabase/supabase-js@2";
import {
  CISA_KEV_CATALOG_URL,
  CISA_KEV_URL,
  type IngestionBatchClaim,
  type IngestionBatchCompletion,
  type IngestionRun,
  type NormalizedKevRecord,
  type RecordOutcome,
  type RunCounters,
} from "./types.ts";

type Source = { id: string };
type Cve = { id: string; description: string | null };
type KevEntry = {
  source_id: string;
  date_added: string;
  due_date: string | null;
  required_action: string;
  known_ransomware_campaign_use: boolean | null;
  notes: string | null;
  source_vendor_name: string | null;
  source_product_name: string | null;
  source_vulnerability_name: string | null;
};

export class RepositoryError extends Error {
  constructor(readonly stage: string, message: string) {
    super(message);
    this.name = "RepositoryError";
  }
}

export class CisaKevRepository {
  constructor(private readonly db: SupabaseClient) {}

  async ensureSource(): Promise<Source> {
    const { data, error } = await this.db.from("sources").upsert({
      source_key: "cisa-kev",
      name: "CISA Known Exploited Vulnerabilities (KEV) Catalog",
      source_type: "government",
      base_url: CISA_KEV_CATALOG_URL,
    }, { onConflict: "source_key" }).select("id").single();
    return assertData(data, error, "source_upsert");
  }

  async getActiveRun(sourceId: string): Promise<IngestionRun | null> {
    const { data, error } = await this.db.rpc("get_active_ingestion_run", {
      p_source_id: sourceId,
      p_collector_type: "cisa-kev",
    });
    assertNoError(error, "run_active_lookup");
    return ((data as IngestionRun[] | null) ?? [])[0] ?? null;
  }

  async createRun(sourceId: string): Promise<{ id: string }> {
    const { data, error } = await this.db.rpc("create_ingestion_run", {
      p_source_id: sourceId,
      p_collector_type: "cisa-kev",
    });
    return { id: assertData(data, error, "run_create") as string };
  }

  async initializeBatching(runId: string, metadata: {
    catalogVersion: string;
    dateReleased: string;
    payloadHash: string;
    payloadBytes: number;
    recordsFound: number;
  }): Promise<IngestionRun> {
    const { data, error } = await this.db.rpc("initialize_ingestion_run_batching", {
      p_run_id: runId,
      p_source_catalog_version: metadata.catalogVersion,
      p_source_released_at: metadata.dateReleased,
      p_source_payload_hash: metadata.payloadHash,
      p_records_found: metadata.recordsFound,
      p_batch_size: 25,
      p_details: {
        feed_url: CISA_KEV_URL,
        payload_bytes: metadata.payloadBytes,
        batch_size: 25,
      },
    });
    const initialized = assertData((data as IngestionRun[] | null)?.[0] ?? null, error, "run_batch_initialize");
    return initialized as IngestionRun;
  }

  async claimBatch(runId: string): Promise<IngestionBatchClaim | null> {
    const { data, error } = await this.db.rpc("claim_ingestion_run_batch", {
      p_run_id: runId,
      p_lease_ttl_seconds: 300,
    });
    assertNoError(error, "batch_claim");
    return ((data as IngestionBatchClaim[] | null) ?? [])[0] ?? null;
  }

  async completeBatch(
    runId: string,
    claim: IngestionBatchClaim,
    counters: Omit<RunCounters, "records_found">,
    firstErrors: Array<Record<string, string>>,
  ): Promise<IngestionBatchCompletion> {
    const { data, error } = await this.db.rpc("complete_ingestion_run_batch", {
      p_run_id: runId,
      p_batch_number: claim.batch_number,
      p_lease_token: claim.lease_token,
      p_records_inserted: counters.records_inserted,
      p_records_updated: counters.records_updated,
      p_records_skipped: counters.records_skipped,
      p_error_count: counters.error_count,
      p_details: { first_errors: firstErrors },
    });
    return assertData((data as IngestionBatchCompletion[] | null)?.[0] ?? null, error, "batch_complete") as IngestionBatchCompletion;
  }

  async releaseBatch(runId: string, claim: IngestionBatchClaim, firstErrors: Array<Record<string, string>>) {
    const { data, error } = await this.db.rpc("release_ingestion_run_batch_lease", {
      p_run_id: runId,
      p_batch_number: claim.batch_number,
      p_lease_token: claim.lease_token,
      p_details: { first_errors: firstErrors },
    });
    assertNoError(error, "batch_release");
    return data === true;
  }

  async abortRun(runId: string, reason: "worker_resource_limit" | "catalog_changed_during_run" | "operator_aborted" | "batch_failed_systemic_cve_source_constraint") {
    const { data, error } = await this.db.rpc("abort_ingestion_run", {
      p_run_id: runId,
      p_error_message: reason,
      p_details: {},
    });
    assertNoError(error, "run_abort");
    return data === true;
  }

  async processRecord(sourceId: string, record: NormalizedKevRecord): Promise<RecordOutcome> {
    const vendorId = await this.ensureVendor(record.vendorSlug, record.vendorName);
    const productId = await this.ensureProduct(vendorId, record.productSlug, record.productName);
    const cve = await this.ensureCve(sourceId, record);
    await this.observeCveSource(cve.id, sourceId, record);
    const kev = await this.findKev(cve.id);
    if (kev && kev.source_id !== sourceId) throw new RepositoryError("kev_lookup", "kev_source_conflict");
    const kevChanged = !kev || hasKevChanged(kev, record);
    if (!kev) await this.insertKev(cve.id, sourceId, record);
    else if (kevChanged) await this.updateKev(cve.id, sourceId, record);
    const relationshipCreated = await this.ensureCveProduct(cve.id, productId, sourceId);

    if (!kev) return "inserted";
    return kevChanged || cve.enriched || relationshipCreated ? "updated" : "skipped";
  }

  private async ensureVendor(slug: string, name: string) {
    const { data, error } = await this.db.from("vendors").select("id").eq("slug", slug).maybeSingle();
    assertNoError(error, "vendor_lookup");
    if (data) return data.id as string;
    const { data: created, error: createError } = await this.db.from("vendors").insert({ slug, name }).select("id").single();
    return (assertData(created, createError, "vendor_create") as { id: string }).id;
  }

  private async ensureProduct(vendorId: string, slug: string, name: string) {
    const { data, error } = await this.db.from("products").select("id").eq("vendor_id", vendorId).eq("slug", slug).maybeSingle();
    assertNoError(error, "product_lookup");
    if (data) return data.id as string;
    const { data: created, error: createError } = await this.db.from("products").insert({ vendor_id: vendorId, slug, name, product_family: null }).select("id").single();
    return (assertData(created, createError, "product_create") as { id: string }).id;
  }

  private async ensureCve(sourceId: string, record: NormalizedKevRecord): Promise<Cve & { enriched: boolean }> {
    const { data, error } = await this.db.from("cves").select("id,description").eq("cve_id", record.cveId).maybeSingle();
    assertNoError(error, "cve_lookup");
    if (!data) {
      const { data: created, error: createError } = await this.db.from("cves").insert({
        cve_id: record.cveId,
        status: "published",
        description: record.shortDescription,
        description_source_id: record.shortDescription ? sourceId : null,
        is_public: false,
      }).select("id,description").single();
      return { ...(assertData(created, createError, "cve_create") as Cve), enriched: false };
    }
    const existing = data as Cve;
    if (!existing.description && record.shortDescription) {
      const { error: updateError } = await this.db.from("cves").update({ description: record.shortDescription, description_source_id: sourceId }).eq("id", existing.id);
      assertNoError(updateError, "cve_update");
      return { ...existing, enriched: true };
    }
    return { ...existing, enriched: false };
  }

  private async observeCveSource(cveId: string, sourceId: string, record: NormalizedKevRecord) {
    const { error } = await this.db.rpc("observe_cve_source", {
      p_cve_id: cveId,
      p_source_id: sourceId,
      p_source_record_id: record.cveId,
      p_source_url: CISA_KEV_URL,
      p_source_published_at: `${record.dateAdded}T00:00:00.000Z`,
      p_source_updated_at: null,
    });
    assertNoError(error, "cve_source_upsert");
  }

  private async findKev(cveId: string) {
    const { data, error } = await this.db.from("kev_entries").select("source_id,date_added,due_date,required_action,known_ransomware_campaign_use,notes,source_vendor_name,source_product_name,source_vulnerability_name").eq("cve_id", cveId).maybeSingle();
    assertNoError(error, "kev_lookup");
    return data as KevEntry | null;
  }

  private async insertKev(cveId: string, sourceId: string, record: NormalizedKevRecord) {
    const { error } = await this.db.from("kev_entries").insert(kevPayload(cveId, sourceId, record));
    assertNoError(error, "kev_create");
  }

  private async updateKev(cveId: string, sourceId: string, record: NormalizedKevRecord) {
    const { error } = await this.db.from("kev_entries").update(kevPayload(cveId, sourceId, record)).eq("cve_id", cveId);
    assertNoError(error, "kev_update");
  }

  private async ensureCveProduct(cveId: string, productId: string, sourceId: string) {
    const { data, error } = await this.db.from("cve_products").select("id").eq("cve_id", cveId).eq("product_id", productId).eq("source_id", sourceId).eq("relationship_type", "affected").maybeSingle();
    assertNoError(error, "cve_product_lookup");
    if (data) return false;
    const { error: createError } = await this.db.from("cve_products").insert({
      cve_id: cveId,
      product_id: productId,
      source_id: sourceId,
      relationship_type: "affected",
      evidence_url: CISA_KEV_URL,
    });
    assertNoError(createError, "cve_product_create");
    return true;
  }
}

function kevPayload(cveId: string, sourceId: string, record: NormalizedKevRecord) {
  return {
    cve_id: cveId,
    source_id: sourceId,
    date_added: record.dateAdded,
    due_date: record.dueDate,
    required_action: record.requiredAction,
    known_ransomware_campaign_use: record.knownRansomwareCampaignUse,
    notes: record.notes,
    source_vendor_name: record.vendorName,
    source_product_name: record.productName,
    source_vulnerability_name: record.vulnerabilityName,
  };
}

function hasKevChanged(existing: KevEntry, record: NormalizedKevRecord) {
  return existing.date_added !== record.dateAdded || existing.due_date !== record.dueDate || existing.required_action !== record.requiredAction ||
    existing.known_ransomware_campaign_use !== record.knownRansomwareCampaignUse || existing.notes !== record.notes ||
    existing.source_vendor_name !== record.vendorName || existing.source_product_name !== record.productName ||
    existing.source_vulnerability_name !== record.vulnerabilityName;
}

function assertData<T>(data: T | null, error: { message: string } | null, context: string) {
  assertNoError(error, context);
  if (!data) throw new RepositoryError(context, "empty_response");
  return data;
}

function assertNoError(error: { message: string } | null, context: string) {
  if (error) throw new RepositoryError(context, error.message);
}