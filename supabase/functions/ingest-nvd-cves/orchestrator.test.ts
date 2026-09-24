import test from "node:test";
import assert from "node:assert/strict";
import { parseNvdRecord } from "./normalizer.ts";
import { processClaim } from "./orchestrator.ts";
import { baseCve } from "./fixtures.ts";
import type { PageClaim } from "./types.ts";

const claim: PageClaim = {
  state_id: "state", run_id: "run", lease_token: "lease",
  window_start: "2026-09-20T00:00:00Z", window_end: "2026-09-22T00:00:00Z",
  start_index: 0, page_size: 25,
};

test("failed record never advances checkpoint; the page is released for retry", async () => {
  let completed = 0; let failed = 0;
  const repository = {
    processRecord: async () => { throw new Error("sensitive raw failure"); },
    complete: async () => { completed++; },
    fail: async (_claim: PageClaim, _code: string, errors: Array<Record<string, string>>) => {
      failed++; assert.equal(errors[0].error, "unexpected_error");
    },
  };
  const result = await processClaim(repository, "source", "bootstrap", claim, "test-only-key",
    async () => ({ totalResults: 1, startIndex: 0, resultsPerPage: 25, records: [parseNvdRecord(baseCve)] }));
  assert.equal(result.status, "failed");
  assert.equal(completed, 0);
  assert.equal(failed, 1);
});
