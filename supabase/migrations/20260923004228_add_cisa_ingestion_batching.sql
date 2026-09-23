ALTER TABLE internal.ingestion_runs
  ADD COLUMN batch_size integer NOT NULL DEFAULT 25,
  ADD COLUMN batches_total integer NOT NULL DEFAULT 0,
  ADD COLUMN batches_completed integer NOT NULL DEFAULT 0,
  ADD COLUMN next_batch_number integer NOT NULL DEFAULT 0,
  ADD COLUMN active_batch_number integer,
  ADD COLUMN active_batch_claimed_at timestamptz,
  ADD COLUMN active_batch_lease_token uuid,
  ADD COLUMN batch_attempts integer NOT NULL DEFAULT 0,
  ADD CONSTRAINT ingestion_runs_batch_size_check CHECK (batch_size > 0),
  ADD CONSTRAINT ingestion_runs_batches_total_check CHECK (batches_total >= 0),
  ADD CONSTRAINT ingestion_runs_batches_completed_check CHECK (batches_completed >= 0),
  ADD CONSTRAINT ingestion_runs_next_batch_number_check CHECK (next_batch_number >= 0),
  ADD CONSTRAINT ingestion_runs_batch_attempts_check CHECK (batch_attempts >= 0),
  ADD CONSTRAINT ingestion_runs_batches_progress_check CHECK (batches_completed <= batches_total),
  ADD CONSTRAINT ingestion_runs_next_batch_progress_check CHECK (next_batch_number <= batches_total),
  ADD CONSTRAINT ingestion_runs_active_batch_check CHECK (
    (active_batch_number IS NULL AND active_batch_claimed_at IS NULL AND active_batch_lease_token IS NULL)
    OR (
      active_batch_number >= 0
      AND active_batch_number < batches_total
      AND active_batch_claimed_at IS NOT NULL
      AND active_batch_lease_token IS NOT NULL
    )
  );

CREATE UNIQUE INDEX ingestion_runs_one_running_source_collector_idx
  ON internal.ingestion_runs (source_id, collector_type)
  WHERE status = 'running';

CREATE INDEX ingestion_runs_running_lease_idx
  ON internal.ingestion_runs (active_batch_claimed_at)
  WHERE status = 'running' AND active_batch_number IS NOT NULL;

CREATE OR REPLACE FUNCTION internal.merge_ingestion_run_details(
  p_current jsonb,
  p_update jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog
AS $$
DECLARE
  v_current jsonb := COALESCE(p_current, '{}'::jsonb);
  v_update jsonb := COALESCE(p_update, '{}'::jsonb);
  v_errors jsonb;
BEGIN
  IF jsonb_typeof(v_current) <> 'object' OR jsonb_typeof(v_update) <> 'object' THEN
    RAISE EXCEPTION 'ingestion details must be JSON objects' USING ERRCODE = '22023';
  END IF;

  IF (v_update ? 'first_errors') AND (
    jsonb_typeof(v_update -> 'first_errors') <> 'array'
    OR jsonb_array_length(v_update -> 'first_errors') > 20
  ) THEN
    RAISE EXCEPTION 'first_errors must contain at most 20 entries' USING ERRCODE = '22023';
  END IF;

  SELECT COALESCE(jsonb_agg(error_entry), '[]'::jsonb)
  INTO v_errors
  FROM (
    SELECT error_entry
    FROM jsonb_array_elements(COALESCE(v_current -> 'first_errors', '[]'::jsonb)
      || COALESCE(v_update -> 'first_errors', '[]'::jsonb)) AS error_entry
    LIMIT 20
  ) AS limited_errors;

  RETURN (v_current || (v_update - 'first_errors'))
    || jsonb_build_object('first_errors', v_errors);
END;
$$;

CREATE OR REPLACE FUNCTION public.get_active_ingestion_run(
  p_source_id uuid,
  p_collector_type text
)
RETURNS TABLE (
  id uuid,
  source_payload_hash text,
  batch_size integer,
  batches_total integer,
  batches_completed integer,
  next_batch_number integer,
  active_batch_number integer,
  active_batch_claimed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF p_source_id IS NULL OR p_collector_type IS NULL OR btrim(p_collector_type) = '' THEN
    RAISE EXCEPTION 'invalid active ingestion run lookup arguments' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT r.id, r.source_payload_hash, r.batch_size, r.batches_total,
    r.batches_completed, r.next_batch_number, r.active_batch_number, r.active_batch_claimed_at
  FROM internal.ingestion_runs AS r
  WHERE r.source_id = p_source_id
    AND r.collector_type = btrim(p_collector_type)
    AND r.status = 'running'
  ORDER BY r.started_at DESC
  LIMIT 1;
END;
$$;

CREATE OR REPLACE FUNCTION public.initialize_ingestion_run_batching(
  p_run_id uuid,
  p_source_catalog_version text,
  p_source_released_at timestamptz,
  p_source_payload_hash text,
  p_records_found integer,
  p_batch_size integer,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS TABLE (id uuid, batch_size integer, batches_total integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
  v_batches_total integer;
BEGIN
  IF p_run_id IS NULL
    OR p_source_catalog_version IS NULL OR btrim(p_source_catalog_version) = ''
    OR char_length(btrim(p_source_catalog_version)) > 200
    OR p_source_released_at IS NULL
    OR p_source_payload_hash IS NULL OR p_source_payload_hash !~* '^[0-9a-f]{64}$'
    OR p_records_found IS NULL OR p_records_found <= 0
    OR p_batch_size IS NULL OR p_batch_size <> 25
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion batching initialization arguments' USING ERRCODE = '22023';
  END IF;

  v_batches_total := (p_records_found + p_batch_size - 1) / p_batch_size;

  RETURN QUERY
  UPDATE internal.ingestion_runs AS r
  SET source_catalog_version = btrim(p_source_catalog_version),
      source_released_at = p_source_released_at,
      source_payload_hash = lower(p_source_payload_hash),
      records_found = p_records_found,
      batch_size = p_batch_size,
      batches_total = v_batches_total,
      batches_completed = 0,
      next_batch_number = 0,
      active_batch_number = NULL,
      active_batch_claimed_at = NULL,
      active_batch_lease_token = NULL,
      batch_attempts = 0,
      details = internal.merge_ingestion_run_details(r.details, v_details)
  WHERE r.id = p_run_id
    AND r.status = 'running'
    AND r.source_payload_hash IS NULL
  RETURNING r.id, r.batch_size, r.batches_total;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'uninitialized running ingestion run not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.claim_ingestion_run_batch(
  p_run_id uuid,
  p_lease_ttl_seconds integer DEFAULT 300
)
RETURNS TABLE (
  batch_number integer,
  lease_token uuid,
  batch_size integer,
  batches_total integer,
  batches_completed integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_run internal.ingestion_runs%ROWTYPE;
  v_batch_number integer;
  v_lease_token uuid;
BEGIN
  IF p_run_id IS NULL OR p_lease_ttl_seconds <> 300 THEN
    RAISE EXCEPTION 'invalid ingestion batch claim arguments' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_run
  FROM internal.ingestion_runs
  WHERE id = p_run_id
  FOR UPDATE;

  IF NOT FOUND OR v_run.status <> 'running' THEN
    RAISE EXCEPTION 'running ingestion run not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_run.source_payload_hash IS NULL OR v_run.batches_total <= 0 THEN
    RAISE EXCEPTION 'ingestion run batching is not initialized' USING ERRCODE = 'P0001';
  END IF;

  IF v_run.active_batch_number IS NOT NULL
    AND v_run.active_batch_claimed_at >= clock_timestamp() - make_interval(secs => p_lease_ttl_seconds) THEN
    RETURN;
  END IF;

  IF v_run.active_batch_number IS NOT NULL THEN
    v_batch_number := v_run.active_batch_number;
  ELSIF v_run.next_batch_number < v_run.batches_total THEN
    v_batch_number := v_run.next_batch_number;
  ELSE
    RETURN;
  END IF;

  v_lease_token := gen_random_uuid();
  UPDATE internal.ingestion_runs
  SET active_batch_number = v_batch_number,
      active_batch_claimed_at = clock_timestamp(),
      active_batch_lease_token = v_lease_token,
      batch_attempts = batch_attempts + 1
  WHERE id = p_run_id;

  RETURN QUERY
  SELECT v_batch_number, v_lease_token, v_run.batch_size, v_run.batches_total, v_run.batches_completed;
END;
$$;

CREATE OR REPLACE FUNCTION public.complete_ingestion_run_batch(
  p_run_id uuid,
  p_batch_number integer,
  p_lease_token uuid,
  p_records_inserted integer,
  p_records_updated integer,
  p_records_skipped integer,
  p_error_count integer,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS TABLE (
  status text,
  batches_completed integer,
  batches_total integer,
  next_batch_number integer,
  records_inserted integer,
  records_updated integer,
  records_skipped integer,
  error_count integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
  IF p_run_id IS NULL OR p_batch_number IS NULL OR p_batch_number < 0 OR p_lease_token IS NULL
    OR p_records_inserted IS NULL OR p_records_inserted < 0
    OR p_records_updated IS NULL OR p_records_updated < 0
    OR p_records_skipped IS NULL OR p_records_skipped < 0
    OR p_error_count IS NULL OR p_error_count < 0
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion batch completion arguments' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  UPDATE internal.ingestion_runs AS r
  SET records_inserted = r.records_inserted + p_records_inserted,
      records_updated = r.records_updated + p_records_updated,
      records_skipped = r.records_skipped + p_records_skipped,
      error_count = r.error_count + p_error_count,
      batches_completed = r.batches_completed + 1,
      next_batch_number = p_batch_number + 1,
      active_batch_number = NULL,
      active_batch_claimed_at = NULL,
      active_batch_lease_token = NULL,
      details = internal.merge_ingestion_run_details(r.details, v_details),
      status = CASE
        WHEN r.batches_completed + 1 = r.batches_total
          THEN CASE WHEN r.error_count + p_error_count > 0 THEN 'partial' ELSE 'succeeded' END
        ELSE r.status
      END,
      finished_at = CASE
        WHEN r.batches_completed + 1 = r.batches_total THEN clock_timestamp()
        ELSE NULL
      END,
      error_message = CASE
        WHEN r.batches_completed + 1 = r.batches_total AND r.error_count + p_error_count > 0
          THEN 'one_or_more_records_failed_validation_or_persistence'
        ELSE r.error_message
      END
  WHERE r.id = p_run_id
    AND r.status = 'running'
    AND r.active_batch_number = p_batch_number
    AND r.active_batch_lease_token = p_lease_token
  RETURNING r.status, r.batches_completed, r.batches_total, r.next_batch_number,
    r.records_inserted, r.records_updated, r.records_skipped, r.error_count;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'active ingestion batch lease not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.release_ingestion_run_batch_lease(
  p_run_id uuid,
  p_batch_number integer,
  p_lease_token uuid,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
  IF p_run_id IS NULL OR p_batch_number IS NULL OR p_batch_number < 0 OR p_lease_token IS NULL
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion batch lease release arguments' USING ERRCODE = '22023';
  END IF;

  UPDATE internal.ingestion_runs AS r
  SET active_batch_number = NULL,
      active_batch_claimed_at = NULL,
      active_batch_lease_token = NULL,
      details = internal.merge_ingestion_run_details(r.details, v_details)
  WHERE r.id = p_run_id
    AND r.status = 'running'
    AND r.active_batch_number = p_batch_number
    AND r.active_batch_lease_token = p_lease_token;

  RETURN FOUND;
END;
$$;

CREATE OR REPLACE FUNCTION public.abort_ingestion_run(
  p_run_id uuid,
  p_error_message text,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
  IF p_run_id IS NULL
    OR p_error_message NOT IN ('worker_resource_limit', 'catalog_changed_during_run', 'operator_aborted')
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion run abort arguments' USING ERRCODE = '22023';
  END IF;

  UPDATE internal.ingestion_runs AS r
  SET status = 'failed',
      finished_at = clock_timestamp(),
      error_message = p_error_message,
      active_batch_number = NULL,
      active_batch_claimed_at = NULL,
      active_batch_lease_token = NULL,
      details = internal.merge_ingestion_run_details(r.details, v_details)
  WHERE r.id = p_run_id AND r.status = 'running';

  RETURN FOUND;
END;
$$;

REVOKE EXECUTE ON FUNCTION internal.merge_ingestion_run_details(jsonb, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.get_active_ingestion_run(uuid, text)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.initialize_ingestion_run_batching(uuid, text, timestamptz, text, integer, integer, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.claim_ingestion_run_batch(uuid, integer)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.complete_ingestion_run_batch(uuid, integer, uuid, integer, integer, integer, integer, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.release_ingestion_run_batch_lease(uuid, integer, uuid, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.abort_ingestion_run(uuid, text, jsonb)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION internal.merge_ingestion_run_details(jsonb, jsonb) TO service_role;
GRANT EXECUTE ON FUNCTION public.get_active_ingestion_run(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.initialize_ingestion_run_batching(uuid, text, timestamptz, text, integer, integer, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_ingestion_run_batch(uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_ingestion_run_batch(uuid, integer, uuid, integer, integer, integer, integer, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.release_ingestion_run_batch_lease(uuid, integer, uuid, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.abort_ingestion_run(uuid, text, jsonb)
  TO service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated;
