import { fetchNvdPage, NvdClientError } from "./nvd-client.ts";
import { RepositoryError } from "./repository.ts";
import type { CollectorMode, NvdPage, NvdRecord, PageClaim, PageCounters, RecordOutcome } from "./types.ts";

type WorkRepository = {
  processRecord(sourceId: string, record: NvdRecord): Promise<RecordOutcome>;
  complete(claim: PageClaim, totalResults: number, pageCount: number, counts: PageCounters): Promise<unknown>;
  fail(claim: PageClaim, code: "fetch_failed" | "invalid_response" | "record_failed" | "checkpoint_failed", errors: Array<Record<string, string>>, errorCount?: number): Promise<void>;
};

export async function processClaim(
  repository: WorkRepository, sourceId: string, mode: CollectorMode,
  claim: PageClaim, apiKey: string,
  fetchPage: typeof fetchNvdPage = fetchNvdPage,
) {
  let page: NvdPage;
  try {
    page = await fetchPage(apiKey, {
      mode, windowStart: claim.window_start, windowEnd: claim.window_end,
      startIndex: claim.start_index,
    });
  } catch (error) {
    const code = error instanceof NvdClientError && ["invalid_json", "invalid_response"].includes(error.code)
      ? "invalid_response" : "fetch_failed";
    await repository.fail(claim, code, [{ stage: "fetch", error: safeCode(error) }]);
    return { status: "failed", counters: { inserted: 0, updated: 0, skipped: 0 }, errors: 1 };
  }

  const counters: PageCounters = { inserted: 0, updated: 0, skipped: 0 };
  const firstErrors: Array<Record<string, string>> = [];
  let errorCount = 0;
  for (const record of page.records) {
    try {
      const outcome = await repository.processRecord(sourceId, record);
      counters[outcome]++;
    } catch (error) {
      errorCount++;
      if (firstErrors.length < 20) firstErrors.push({
        cve_id: safeText(record.cveId), stage: error instanceof RepositoryError ? safeText(error.stage) : "record",
        error: safeCode(error),
      });
    }
  }
  if (errorCount) {
    // A partial page never advances the checkpoint. Successful rows are safe to replay.
    await repository.fail(claim, "record_failed", firstErrors, errorCount);
    return { status: "failed", counters, errors: errorCount };
  }
  try {
    const completion = await repository.complete(claim, page.totalResults, page.records.length, counters);
    return { status: "succeeded", counters, errors: 0, completion };
  } catch (error) {
    await repository.fail(claim, "checkpoint_failed", [{ stage: "checkpoint", error: safeCode(error) }]).catch(() => undefined);
    throw new RepositoryError("checkpoint_failed");
  }
}

function safeCode(error: unknown) {
  if (error instanceof NvdClientError) return error.code;
  if (error instanceof RepositoryError) return error.stage;
  return "unexpected_error";
}
function safeText(value: string) {
  return value.replace(/[^A-Za-z0-9_\-]/g, "").slice(0, 80);
}
