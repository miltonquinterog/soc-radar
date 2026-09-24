# ADR 003 — NVD collector (pre-deployment)

Status: RPC migrations applied and validated; the Edge Function has not been deployed.

## Scope and access

The Edge Function uses the official NVD CVE 2.0 endpoint and reads `NVD_API_KEY`
only from its Edge Function environment. The inbound function requires a separate
named Supabase Secret API Key, `nvd_ingestion`, via `secret:nvd_ingestion`.
Neither value belongs in Git, frontend code, SQL migrations, responses or logs.
The service-side Supabase client is used only within the Edge Function. The
internal schema remains outside Data API; narrow public-schema RPCs grant
EXECUTE exclusively to `service_role`.

## Unit of work and state

One invocation claims and processes one NVD page of **25 CVE**. NVD
`resultsPerPage` and persistence batch size are therefore identical. A first
bootstrap or incremental window must be explicit and at most seven days;
bootstrap can never silently request the historical catalogue. A continuing
bootstrap uses the stored window and `next_start_index`. After an incremental
window completes, the next one begins at `high_water_mark - overlap_hours`
(default 24 hours), bounded to seven days, and ends at the invocation time.
Overlap is intentionally reread and made safe by idempotent writes.

`internal.collector_state` is the durable position, not the run audit log.
The applied RPC migration adds a five-minute lease, token, active run ID and a
three-attempt limit. Claiming is serialized by locking the NVD source row.
Page completion advances the checkpoint and closes its run in one transaction.
On a record error the page is not checkpointed; a retry replays any successful
records. An expired lease closes its run as failed before a new claim. Three
failed/expired attempts mark the state failed for operator review. No Cron is
configured in this phase.

## Canonical fields and provenance

NVD has its own `source_key=nvd` with `source_type=vulnerability_database`.
`cve_sources` records NVD's exact status, URL, publication and modification
time using a new NVD-only observation RPC; CISA's RPC is unchanged. The first
observation timestamp never changes. The canonical description is filled if
empty, or changed only when its `description_source_id` is NVD. An existing
publication date is not replaced. Modification time never moves backward.
Only explicitly mapped NVD statuses affect canonical status. `is_public` is
neither inserted nor updated: its database default remains false.

References are deduplicated by normalized HTTP(S) URL. An existing URL keeps
its existing `source_id` and other fields, even when NVD also lists it. No
external reference content is fetched. CWE, CPE, configurations, SSVC and
version ranges remain deferred.

## Operational CVSS selection

The metric's `source_id` identifies NVD as the transport source;
`metric_source_identifier` preserves the payload's contributor. Every distinct
`(version, metric_type, contributor)` is stored, including secondary sources.
`metric_type=primary` means NVD labelled that contribution Primary; it does
not itself set `is_primary`.

For NVD contributions, select exactly one candidate in this order:

1. NVD type Primary, then Secondary, then other;
2. highest version (4.0 > 3.1 > 3.0 > 2.0);
3. NVD's own contributor `nvd@nist.gov` before other contributors;
4. lexicographically smallest contributor, then vector, for a stable tie.

Only the winner is marked `is_primary=true`. If another source already owns
the operational primary metric, the NVD collector does not displace it.
No severity column or UI severity derivation is added here. Changed scores or
vectors update the existing contributor row; identical observations are skips.

## Network behavior and risks

The client sends `apiKey` to NVD, not an Authorization bearer token. It has a
conservative isolate-local minimum interval of 1.2 seconds, at most three
attempts, exponential backoff with jitter, `Retry-After` support for 429, and
10-second per-request timeout. A Retry-After above 30 seconds stops this
invocation rather than retrying early. This limiter is not global across Edge
isolates; deployment must keep invocation concurrency low. NVD pagination can
change as upstream records change, so incremental overlap and later full
reconciliation remain necessary.
