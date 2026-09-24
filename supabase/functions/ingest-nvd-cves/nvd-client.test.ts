import test from "node:test";
import assert from "node:assert/strict";
import { baseCve, pageFor } from "./fixtures.ts";
import { fetchNvdPage, NvdClientError, retryAfterMs } from "./nvd-client.ts";

const input = { mode: "bootstrap" as const, windowStart: "2026-09-20T00:00:00Z", windowEnd: "2026-09-22T00:00:00Z", startIndex: 0 };
const noSleep = async () => {};

test("client sends bounded page, date filters and apiKey header", async () => {
  const observed = { url: new URL("https://example.invalid"), headers: new Headers() };
  const page = await fetchNvdPage("test-only-key", input, { sleep: noSleep, fetcher: async (request, init) => {
    observed.url = new URL(String(request));
    observed.headers = new Headers(init?.headers);
    return Response.json(pageFor(baseCve));
  } });
  assert.equal(page.records.length, 1);
  assert.equal(observed.url.searchParams.get("resultsPerPage"), "25");
  assert.equal(observed.url.searchParams.get("pubStartDate"), input.windowStart);
  assert.equal(observed.headers.get("apiKey"), "test-only-key");
  assert.equal(observed.headers.get("Authorization"), null);
});

test("incremental mode uses last-modified filters", async () => {
  let url = new URL("https://example.invalid");
  await fetchNvdPage("test-only-key", { ...input, mode: "incremental" }, { sleep: noSleep, fetcher: async (request) => {
    url = new URL(String(request)); return Response.json(pageFor());
  } });
  assert.equal(url.searchParams.get("lastModStartDate"), input.windowStart);
  assert.equal(url.searchParams.get("pubStartDate"), null);
});

test("429 honors Retry-After and retries with a cap", async () => {
  let calls = 0; const waits: number[] = [];
  await fetchNvdPage("test-only-key", input, {
    sleep: async (ms) => { waits.push(ms); }, random: () => 0,
    fetcher: async () => ++calls === 1
      ? new Response("", { status: 429, headers: { "Retry-After": "3" } })
      : Response.json(pageFor()),
  });
  assert.equal(calls, 2);
  assert.ok(waits.some((ms) => ms >= 3_000));
  assert.equal(retryAfterMs("2"), 2_000);
});

test("5xx retries at most three times", async () => {
  let calls = 0;
  await assert.rejects(fetchNvdPage("test-only-key", input, {
    sleep: noSleep, random: () => 0,
    fetcher: async () => { calls++; return new Response("", { status: 503 }); },
  }), (error: unknown) => error instanceof NvdClientError && error.code === "server_error");
  assert.equal(calls, 3);
});

test("timeout retries at most three times", async () => {
  let calls = 0;
  await assert.rejects(fetchNvdPage("test-only-key", input, {
    sleep: noSleep, random: () => 0,
    fetcher: async () => { calls++; throw new DOMException("timeout", "TimeoutError"); },
  }), (error: unknown) => error instanceof NvdClientError && error.code === "timeout");
  assert.equal(calls, 3);
});

test("invalid JSON is rejected without logging payload", async () => {
  await assert.rejects(fetchNvdPage("test-only-key", input, {
    sleep: noSleep, fetcher: async () => new Response("invalid-json", { status: 200 }),
  }), (error: unknown) => error instanceof NvdClientError && error.code === "invalid_json");
});
