import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "npm:@supabase/server";
import { fetchCisaKevCatalog } from "./cisa.ts";
import { normalizeKevRecord } from "./normalizer.ts";
import { CisaKevRepository, RepositoryError } from "./repository.ts";
import { type IngestionBatchClaim, type RunCounters } from "./types.ts";

const MAX_FIRST_ERRORS = 20;

Deno.serve(withSupabase({ auth: "secret:cisa_ingestion" }, async (request, ctx) => {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const startedAt = Date.now();
  const repository = new CisaKevRepository(ctx.supabaseAdmin);
  let runId: string | null = null;
  let claim: IngestionBatchClaim | null = null;
  const counters = emptyCounters();
  const firstErrors: Array<Record<string, string>> = [];

  try {
    const source = await repository.ensureSource();
    const fetched = await fetchCisaKevCatalog();
    const activeRun = await repository.getActiveRun(source.id);

    if (activeRun && activeRun.source_payload_hash !== fetched.payloadHash) {
      await repository.abortRun(activeRun.id, "catalog_changed_during_run");
    }

    const reusableRun = activeRun && activeRun.source_payload_hash === fetched.payloadHash ? activeRun : null;
    if (reusableRun) {
      runId = reusableRun.id;
    } else {
      runId = (await repository.createRun(source.id)).id;
      await repository.initializeBatching(runId, {
        catalogVersion: fetched.catalog.catalogVersion,
        dateReleased: fetched.catalog.dateReleased,
        payloadHash: fetched.payloadHash,
        payloadBytes: fetched.payloadBytes,
        recordsFound: fetched.catalog.vulnerabilities.length,
      });
    }

    claim = await repository.claimBatch(runId);
    if (!claim) {
      const currentRun = await repository.getActiveRun(source.id);
      return json({
        status: currentRun ? "running" : "succeeded",
        run_id: runId,
        message: currentRun ? "batch_already_leased" : "no_remaining_batches",
        duration_ms: Date.now() - startedAt,
      }, 200);
    }

    const start = claim.batch_number * claim.batch_size;
    const batch = fetched.catalog.vulnerabilities.slice(start, start + claim.batch_size);
    counters.records_found = batch.length;

    for (const rawRecord of batch) {
      let cveId = "unknown";
      try {
        const record = normalizeKevRecord(rawRecord);
        cveId = record.cveId;
        const outcome = await repository.processRecord(source.id, record);
        if (outcome === "inserted") counters.records_inserted += 1;
        if (outcome === "updated") counters.records_updated += 1;
        if (outcome === "skipped") counters.records_skipped += 1;
      } catch (error) {
        counters.error_count += 1;
        addFirstError(firstErrors, cveId, error);
      }
    }

    const completed = await repository.completeBatch(runId, claim, counters, firstErrors);
    return json({
      status: completed.status,
      run_id: runId,
      batch_number: claim.batch_number + 1,
      batches_total: completed.batches_total,
      batches_completed: completed.batches_completed,
      remaining_batches: completed.batches_total - completed.batches_completed,
      records_inserted: counters.records_inserted,
      records_updated: counters.records_updated,
      records_skipped: counters.records_skipped,
      errors: counters.error_count,
      cumulative_records_inserted: completed.records_inserted,
      cumulative_records_updated: completed.records_updated,
      cumulative_records_skipped: completed.records_skipped,
      cumulative_errors: completed.error_count,
      duration_ms: Date.now() - startedAt,
    }, completed.status === "failed" ? 500 : 200);
  } catch (error) {
    if (runId && claim) {
      addFirstError(firstErrors, "batch", error);
      await repository.releaseBatch(runId, claim, firstErrors).catch(() => undefined);
    }
    return json({
      status: "failed",
      run_id: runId,
      error: "ingestion_batch_failed",
      duration_ms: Date.now() - startedAt,
    }, 500);
  }
}));

function emptyCounters(): RunCounters {
  return { records_found: 0, records_inserted: 0, records_updated: 0, records_skipped: 0, error_count: 0 };
}

function addFirstError(errors: Array<Record<string, string>>, cveId: string, error: unknown) {
  if (errors.length >= MAX_FIRST_ERRORS) return;
  const stage = error instanceof RepositoryError ? error.stage : "record_normalize";
  const message = error instanceof Error ? error.message : "unknown_error";
  errors.push({ cve_id: sanitize(cveId), stage: sanitize(stage), error: sanitize(message) });
}

function sanitize(value: string) {
  return value.replace(/[\r\n\t]+/g, " ").replace(/[^a-zA-Z0-9_ .,:;()\-]/g, "").trim().slice(0, 240) || "unknown_error";
}

function json(body: unknown, status: number) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}