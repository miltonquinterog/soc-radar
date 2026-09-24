import { parseNvdPage } from "./normalizer.ts";
import type { CollectorMode, NvdPage } from "./types.ts";

export const NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const NVD_PAGE_SIZE = 25;
const MAX_ATTEMPTS = 3;
const MIN_REQUEST_GAP_MS = 1_200;
let lastRequestAt = 0;

export class NvdClientError extends Error {
  readonly code: "rate_limited" | "server_error" | "timeout" | "invalid_json" | "invalid_response" | "request_failed";
  constructor(code: NvdClientError["code"]) {
    super(code);
    this.code = code;
    this.name = "NvdClientError";
  }
}

export type NvdFetchOptions = {
  fetcher?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
};

export async function fetchNvdPage(
  apiKey: string,
  input: { mode: CollectorMode; windowStart: string; windowEnd: string; startIndex: number },
  options: NvdFetchOptions = {},
): Promise<NvdPage> {
  if (!apiKey) throw new NvdClientError("request_failed");
  const url = new URL(NVD_CVE_API);
  const prefix = input.mode === "bootstrap" ? "pub" : "lastMod";
  url.searchParams.set(`${prefix}StartDate`, input.windowStart);
  url.searchParams.set(`${prefix}EndDate`, input.windowEnd);
  url.searchParams.set("startIndex", String(input.startIndex));
  url.searchParams.set("resultsPerPage", String(NVD_PAGE_SIZE));
  const fetcher = options.fetcher ?? fetch;
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const random = options.random ?? Math.random;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const gap = MIN_REQUEST_GAP_MS - (Date.now() - lastRequestAt);
    if (gap > 0) await sleep(gap);
    lastRequestAt = Date.now();
    let response: Response;
    try {
      response = await fetcher(url, {
        method: "GET",
        headers: { apiKey, Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      const code = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")
        ? "timeout" : "request_failed";
      if (attempt === MAX_ATTEMPTS) throw new NvdClientError(code);
      await sleep(backoff(attempt, random));
      continue;
    }
    if (response.status === 429 || response.status >= 500) {
      const code = response.status === 429 ? "rate_limited" : "server_error";
      if (attempt === MAX_ATTEMPTS) throw new NvdClientError(code);
      const retryAfter = retryAfterMs(response.headers.get("Retry-After"));
      if (retryAfter !== null && retryAfter > 30_000) throw new NvdClientError(code);
      await sleep(Math.max(retryAfter ?? 0, backoff(attempt, random)));
      continue;
    }
    if (!response.ok) throw new NvdClientError("request_failed");
    if (Number(response.headers.get("Content-Length") ?? 0) > 4_000_000) throw new NvdClientError("invalid_response");
    let value: unknown;
    try {
      const body = await response.text();
      if (body.length > 4_000_000) throw new NvdClientError("invalid_response");
      value = JSON.parse(body);
    } catch (error) {
      if (error instanceof NvdClientError) throw error;
      throw new NvdClientError("invalid_json");
    }
    try {
      const page = parseNvdPage(value);
      if (page.startIndex !== input.startIndex) throw new Error("page_offset_mismatch");
      return page;
    } catch {
      throw new NvdClientError("invalid_response");
    }
  }
  throw new NvdClientError("request_failed");
}

function backoff(attempt: number, random: () => number) {
  return Math.round(1_000 * 2 ** (attempt - 1) + random() * 500);
}

export function retryAfterMs(header: string | null, now = Date.now()): number | null {
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1_000);
  const timestamp = Date.parse(header);
  return Number.isFinite(timestamp) ? Math.max(0, timestamp - now) : null;
}
