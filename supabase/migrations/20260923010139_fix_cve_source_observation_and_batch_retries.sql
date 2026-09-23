CREATE OR REPLACE FUNCTION public.observe_cve_source(
  p_cve_id uuid,
  p_source_id uuid,
  p_source_record_id text,
  p_source_url text,
  p_source_published_at timestamptz,
  p_source_updated_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE
  v_observed_at timestamptz := clock_timestamp();
BEGIN
  IF p_cve_id IS NULL
    OR p_source_id IS NULL
    OR p_source_record_id IS NULL OR btrim(p_source_record_id) = ''
    OR p_source_url IS NULL OR btrim(p_source_url) = ''
    OR p_source_published_at IS NULL THEN
    RAISE EXCEPTION 'invalid CVE source observation arguments' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.cve_sources (
    cve_id,
    source_id,
    source_record_id,
    source_url,
    source_published_at,
    source_updated_at,
    first_seen_at,
    last_seen_at
  )
  VALUES (
    p_cve_id,
    p_source_id,
    btrim(p_source_record_id),
    btrim(p_source_url),
    p_source_published_at,
    p_source_updated_at,
    v_observed_at,
    v_observed_at
  )
  ON CONFLICT (cve_id, source_id)
  DO UPDATE SET
    source_record_id = EXCLUDED.source_record_id,
    source_url = EXCLUDED.source_url,
    source_published_at = EXCLUDED.source_published_at,
    source_updated_at = EXCLUDED.source_updated_at,
    last_seen_at = v_observed_at;
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

  IF v_run.batch_attempts >= 3 THEN
    UPDATE internal.ingestion_runs
    SET status = 'failed',
        finished_at = clock_timestamp(),
        error_message = 'batch_retry_limit_exceeded',
        active_batch_number = NULL,
        active_batch_claimed_at = NULL,
        active_batch_lease_token = NULL
    WHERE id = p_run_id;
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
  v_run internal.ingestion_runs%ROWTYPE;
  v_success_count integer;
  v_expected_records integer;
  v_systemic_failure boolean;
BEGIN
  IF p_run_id IS NULL OR p_batch_number IS NULL OR p_batch_number < 0 OR p_lease_token IS NULL
    OR p_records_inserted IS NULL OR p_records_inserted < 0
    OR p_records_updated IS NULL OR p_records_updated < 0
    OR p_records_skipped IS NULL OR p_records_skipped < 0
    OR p_error_count IS NULL OR p_error_count < 0
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion batch completion arguments' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_run
  FROM internal.ingestion_runs
  WHERE id = p_run_id
  FOR UPDATE;

  IF NOT FOUND
    OR v_run.status <> 'running'
    OR v_run.active_batch_number <> p_batch_number
    OR v_run.active_batch_lease_token <> p_lease_token THEN
    RAISE EXCEPTION 'active ingestion batch lease not found' USING ERRCODE = 'P0002';
  END IF;

  v_success_count := p_records_inserted + p_records_updated + p_records_skipped;
  v_expected_records := LEAST(
    v_run.batch_size,
    v_run.records_found - (p_batch_number * v_run.batch_size)
  );

  IF v_expected_records <= 0 OR v_success_count + p_error_count <> v_expected_records THEN
    RAISE EXCEPTION 'batch outcome counters do not match claimed batch size' USING ERRCODE = '22023';
  END IF;

  v_systemic_failure := v_success_count = 0 AND p_error_count = v_expected_records;

  IF v_systemic_failure THEN
    RETURN QUERY
    UPDATE internal.ingestion_runs AS r
    SET active_batch_number = NULL,
        active_batch_claimed_at = NULL,
        active_batch_lease_token = NULL,
        details = internal.merge_ingestion_run_details(
          r.details,
          v_details || jsonb_build_object(
            'last_systemic_batch_failure',
            jsonb_build_object(
              'batch_number', p_batch_number,
              'attempt', r.batch_attempts,
              'records_failed', p_error_count
            )
          )
        ),
        status = CASE WHEN r.batch_attempts >= 3 THEN 'failed' ELSE 'running' END,
        finished_at = CASE WHEN r.batch_attempts >= 3 THEN clock_timestamp() ELSE NULL END,
        error_message = CASE
          WHEN r.batch_attempts >= 3 THEN 'batch_retry_limit_exceeded'
          ELSE r.error_message
        END
    WHERE r.id = p_run_id
    RETURNING r.status, r.batches_completed, r.batches_total, r.next_batch_number,
      r.records_inserted, r.records_updated, r.records_skipped, r.error_count;
    RETURN;
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
      batch_attempts = 0,
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
  RETURNING r.status, r.batches_completed, r.batches_total, r.next_batch_number,
    r.records_inserted, r.records_updated, r.records_skipped, r.error_count;
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
    OR p_error_message NOT IN (
      'worker_resource_limit',
      'catalog_changed_during_run',
      'operator_aborted',
      'batch_failed_systemic_cve_source_constraint'
    )
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

REVOKE EXECUTE ON FUNCTION public.observe_cve_source(uuid, uuid, text, text, timestamptz, timestamptz)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.claim_ingestion_run_batch(uuid, integer)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.complete_ingestion_run_batch(uuid, integer, uuid, integer, integer, integer, integer, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.abort_ingestion_run(uuid, text, jsonb)
  FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.observe_cve_source(uuid, uuid, text, text, timestamptz, timestamptz)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_ingestion_run_batch(uuid, integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_ingestion_run_batch(uuid, integer, uuid, integer, integer, integer, integer, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.abort_ingestion_run(uuid, text, jsonb) TO service_role;