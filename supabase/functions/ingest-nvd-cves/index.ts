import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { withSupabase } from "npm:@supabase/server";
import { NvdRepository } from "./repository.ts";
import { processClaim } from "./orchestrator.ts";
import type { CollectorMode } from "./types.ts";

Deno.serve(withSupabase({ auth: "secret:nvd_ingestion" }, async (request, ctx) => {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  // Read only inside the Edge Function. Never return, print or persist this value.
  const nvdApiKey = Deno.env.get("NVD_API_KEY");
  if (!nvdApiKey) return json({ error: "nvd_key_not_configured" }, 503);
  let input: { mode: CollectorMode; windowStart: string | null; windowEnd: string | null };
  try {
    const body = await request.json() as Record<string, unknown>;
    if (!body || (body.mode !== "bootstrap" && body.mode !== "incremental") ||
      (body.window_start != null && typeof body.window_start !== "string") ||
      (body.window_end != null && typeof body.window_end !== "string")) {
      return json({ error: "invalid_request" }, 400);
    }
    input = {
      mode: body.mode, windowStart: (body.window_start as string | null) ?? null,
      windowEnd: (body.window_end as string | null) ?? null,
    };
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const repository = new NvdRepository(ctx.supabaseAdmin);
  let runId: string | null = null;
  try {
    const sourceId = await repository.ensureSource();
    const claim = await repository.claim(sourceId, input.mode, input.windowStart, input.windowEnd);
    if (!claim) return json({ status: "no_page_claimed" }, 200);
    runId = claim.run_id;
    const result = await processClaim(repository, sourceId, input.mode, claim, nvdApiKey);
    return json({
      status: result.status, run_id: runId, start_index: claim.start_index,
      page_size: claim.page_size, ...result.counters, errors: result.errors,
    }, result.status === "failed" ? 503 : 200);
  } catch {
    // No exception message, request header or NVD payload is sent to the caller/logs.
    return json({ status: "failed", run_id: runId, error: "nvd_page_failed" }, 500);
  }
}));

function json(body: unknown, status: number) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}
