-- Local prerequisite for the NVD collector. Apply only in a separately approved deployment.
-- Internal state remains outside the Data API; all public RPCs are service_role-only.

ALTER TABLE internal.collector_state
  ADD COLUMN lease_token uuid,
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN active_run_id uuid REFERENCES internal.ingestion_runs(id) ON DELETE RESTRICT,
  ADD COLUMN page_attempts integer NOT NULL DEFAULT 0 CHECK (page_attempts BETWEEN 0 AND 3),
  ADD CONSTRAINT collector_state_lease_pair_check CHECK (
    (lease_token IS NULL AND lease_expires_at IS NULL AND active_run_id IS NULL)
    OR (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND active_run_id IS NOT NULL)
  );

CREATE OR REPLACE FUNCTION public.observe_nvd_cve_source(
  p_cve_id uuid,
  p_source_id uuid,
  p_source_record_id text,
  p_source_url text,
  p_source_published_at timestamptz,
  p_source_updated_at timestamptz,
  p_source_status text
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE v_now timestamptz := clock_timestamp();
BEGIN
  IF p_cve_id IS NULL OR p_source_id IS NULL OR p_source_record_id IS NULL
    OR btrim(p_source_record_id) = '' OR p_source_url IS NULL OR btrim(p_source_url) = ''
    OR p_source_published_at IS NULL OR p_source_status IS NULL OR btrim(p_source_status) = ''
    OR NOT EXISTS (SELECT 1 FROM public.sources WHERE id = p_source_id AND source_key = 'nvd')
  THEN RAISE EXCEPTION 'invalid NVD observation' USING ERRCODE = '22023'; END IF;

  INSERT INTO public.cve_sources (
    cve_id, source_id, source_record_id, source_url, source_published_at,
    source_updated_at, source_status, first_seen_at, last_seen_at
  ) VALUES (
    p_cve_id, p_source_id, btrim(p_source_record_id), btrim(p_source_url),
    p_source_published_at, p_source_updated_at, btrim(p_source_status), v_now, v_now
  ) ON CONFLICT (cve_id, source_id) DO UPDATE SET
    source_record_id = EXCLUDED.source_record_id,
    source_url = EXCLUDED.source_url,
    source_published_at = EXCLUDED.source_published_at,
    source_updated_at = EXCLUDED.source_updated_at,
    source_status = EXCLUDED.source_status,
    last_seen_at = GREATEST(public.cve_sources.last_seen_at, v_now);
END;
$$;

CREATE OR REPLACE FUNCTION public.claim_nvd_page(
  p_source_id uuid, p_mode text,
  p_window_start timestamptz DEFAULT NULL, p_window_end timestamptz DEFAULT NULL
) RETURNS TABLE (
  state_id uuid, run_id uuid, lease_token uuid,
  window_start timestamptz, window_end timestamptz,
  start_index integer, page_size integer
) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_state internal.collector_state%ROWTYPE;
  v_now timestamptz := clock_timestamp();
  v_start timestamptz;
  v_end timestamptz;
  v_run_id uuid;
  v_token uuid;
BEGIN
  IF p_source_id IS NULL OR p_mode IS NULL OR p_mode NOT IN ('bootstrap', 'incremental')
    OR (p_window_start IS NULL) <> (p_window_end IS NULL)
    OR NOT EXISTS (SELECT 1 FROM public.sources WHERE id = p_source_id AND source_key = 'nvd')
  THEN RAISE EXCEPTION 'invalid NVD claim' USING ERRCODE = '22023'; END IF;

  -- Serialize first-time state creation as well as subsequent claims.
  PERFORM 1 FROM public.sources WHERE id = p_source_id FOR UPDATE;

  SELECT * INTO v_state FROM internal.collector_state
    WHERE source_id = p_source_id AND collector_type = 'nvd-cve' AND mode = p_mode FOR UPDATE;

  IF NOT FOUND OR v_state.status = 'completed' THEN
    IF p_mode = 'bootstrap' AND (p_window_start IS NULL OR
      (v_state.id IS NOT NULL AND p_window_start = v_state.window_start AND p_window_end = v_state.window_end))
    THEN RAISE EXCEPTION 'bootstrap requires a new explicit window' USING ERRCODE = '22023'; END IF;
    IF p_window_start IS NULL THEN
      IF v_state.high_water_mark IS NULL THEN
        RAISE EXCEPTION 'initial incremental window must be explicit' USING ERRCODE = '22023';
      END IF;
      v_start := GREATEST(v_state.high_water_mark - make_interval(hours => v_state.overlap_hours), v_now - interval '7 days');
      v_end := v_now;
    ELSE v_start := p_window_start; v_end := p_window_end;
    END IF;
    IF v_start IS NULL OR v_end IS NULL OR v_start >= v_end
      OR v_end > v_now + interval '1 minute' OR v_end - v_start > interval '7 days'
    THEN RAISE EXCEPTION 'NVD window must be bounded to seven days' USING ERRCODE = '22023'; END IF;
    INSERT INTO internal.collector_state (
      source_id, collector_type, mode, status, window_start, window_end, next_start_index
    ) VALUES (p_source_id, 'nvd-cve', p_mode, 'running', v_start, v_end, 0)
    ON CONFLICT (source_id, collector_type, mode) DO UPDATE SET
      status = 'running', window_start = EXCLUDED.window_start,
      window_end = EXCLUDED.window_end, next_start_index = 0, page_attempts = 0
    RETURNING * INTO v_state;
  ELSIF v_state.status = 'failed' THEN
    RAISE EXCEPTION 'NVD state failed; operator review required' USING ERRCODE = 'P0001';
  ELSIF p_window_start IS NOT NULL AND
    (p_window_start <> v_state.window_start OR p_window_end <> v_state.window_end) THEN
    RAISE EXCEPTION 'NVD active window mismatch' USING ERRCODE = '22023';
  END IF;

  IF v_state.lease_expires_at > v_now THEN RETURN; END IF;
  IF v_state.active_run_id IS NOT NULL THEN
    UPDATE internal.ingestion_runs SET status = 'failed', finished_at = v_now,
      error_message = 'page_lease_expired', error_count = 1
    WHERE id = v_state.active_run_id AND status = 'running';
  END IF;
  IF v_state.page_attempts >= 3 THEN
    UPDATE internal.collector_state SET status = 'failed', lease_token = NULL,
      lease_expires_at = NULL, active_run_id = NULL WHERE id = v_state.id;
    RETURN;
  END IF;

  INSERT INTO internal.ingestion_runs (source_id, collector_type, status, details)
  VALUES (p_source_id, 'nvd-cve', 'running', jsonb_build_object(
    'mode', p_mode, 'window_start', v_state.window_start,
    'window_end', v_state.window_end, 'start_index', v_state.next_start_index,
    'page_size', 25
  )) RETURNING id INTO v_run_id;
  v_token := gen_random_uuid();
  UPDATE internal.collector_state SET lease_token = v_token,
    lease_expires_at = v_now + interval '5 minutes', active_run_id = v_run_id,
    page_attempts = page_attempts + 1 WHERE id = v_state.id;
  RETURN QUERY SELECT v_state.id, v_run_id, v_token,
    v_state.window_start, v_state.window_end, v_state.next_start_index, 25;
END;
$$;

CREATE OR REPLACE FUNCTION public.complete_nvd_page(
  p_state_id uuid, p_run_id uuid, p_lease_token uuid,
  p_total_results integer, p_page_count integer,
  p_inserted integer, p_updated integer, p_skipped integer
) RETURNS TABLE (status text, next_start_index integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE v_state internal.collector_state%ROWTYPE; v_next integer; v_done boolean;
BEGIN
  IF p_state_id IS NULL OR p_run_id IS NULL OR p_lease_token IS NULL
    OR p_total_results IS NULL OR p_total_results < 0
    OR p_page_count IS NULL OR p_page_count < 0 OR p_page_count > 25
    OR p_inserted IS NULL OR p_inserted < 0 OR p_updated IS NULL OR p_updated < 0
    OR p_skipped IS NULL OR p_skipped < 0 OR p_inserted + p_updated + p_skipped <> p_page_count
  THEN RAISE EXCEPTION 'invalid NVD completion' USING ERRCODE = '22023'; END IF;
  SELECT * INTO v_state FROM internal.collector_state WHERE id = p_state_id FOR UPDATE;
  IF NOT FOUND OR v_state.status <> 'running' OR v_state.active_run_id <> p_run_id
    OR v_state.lease_token <> p_lease_token OR v_state.lease_expires_at <= clock_timestamp()
  THEN RAISE EXCEPTION 'NVD page lease invalid or expired' USING ERRCODE = 'P0002'; END IF;
  v_next := v_state.next_start_index + p_page_count;
  IF v_next > p_total_results OR (p_page_count = 0 AND v_state.next_start_index < p_total_results)
  THEN RAISE EXCEPTION 'inconsistent NVD pagination' USING ERRCODE = '22023'; END IF;
  v_done := v_next >= p_total_results;
  UPDATE internal.ingestion_runs SET status = 'succeeded', finished_at = clock_timestamp(),
    records_found = p_page_count, records_inserted = p_inserted,
    records_updated = p_updated, records_skipped = p_skipped,
    batches_total = 1, batches_completed = 1, next_batch_number = 1,
    details = details || jsonb_build_object('total_results', p_total_results)
  WHERE id = p_run_id AND status = 'running';
  IF NOT FOUND THEN RAISE EXCEPTION 'running NVD run missing' USING ERRCODE = 'P0002'; END IF;
  UPDATE internal.collector_state SET next_start_index = v_next,
    status = CASE WHEN v_done THEN 'completed' ELSE 'running' END,
    high_water_mark = CASE WHEN v_done AND mode = 'incremental' THEN window_end ELSE high_water_mark END,
    lease_token = NULL, lease_expires_at = NULL, active_run_id = NULL, page_attempts = 0
  WHERE id = p_state_id;
  RETURN QUERY SELECT CASE WHEN v_done THEN 'completed' ELSE 'running' END, v_next;
END;
$$;

CREATE OR REPLACE FUNCTION public.fail_nvd_page(
  p_state_id uuid, p_run_id uuid, p_lease_token uuid,
  p_error_code text, p_error_count integer DEFAULT 1,
  p_first_errors jsonb DEFAULT '[]'::jsonb
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE v_state internal.collector_state%ROWTYPE; v_status text;
BEGIN
  IF p_state_id IS NULL OR p_run_id IS NULL OR p_lease_token IS NULL
    OR p_error_code IS NULL OR p_error_code NOT IN ('fetch_failed','invalid_response','record_failed','checkpoint_failed')
    OR p_error_count IS NULL OR p_error_count < 1 OR p_error_count > 25
    OR jsonb_typeof(p_first_errors) <> 'array' OR jsonb_array_length(p_first_errors) > 20
  THEN RAISE EXCEPTION 'invalid NVD failure report' USING ERRCODE = '22023'; END IF;
  SELECT * INTO v_state FROM internal.collector_state WHERE id = p_state_id FOR UPDATE;
  IF NOT FOUND OR v_state.status <> 'running' OR v_state.active_run_id <> p_run_id
    OR v_state.lease_token <> p_lease_token
  THEN RAISE EXCEPTION 'NVD page lease missing' USING ERRCODE = 'P0002'; END IF;
  v_status := CASE WHEN v_state.page_attempts >= 3 THEN 'failed' ELSE 'running' END;
  UPDATE internal.ingestion_runs SET status = 'failed', finished_at = clock_timestamp(),
    error_count = p_error_count, error_message = p_error_code,
    details = details || jsonb_build_object('first_errors', p_first_errors)
  WHERE id = p_run_id AND status = 'running';
  UPDATE internal.collector_state SET status = v_status,
    lease_token = NULL, lease_expires_at = NULL, active_run_id = NULL
  WHERE id = p_state_id;
  RETURN v_status;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.observe_nvd_cve_source(uuid,uuid,text,text,timestamptz,timestamptz,text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.claim_nvd_page(uuid,text,timestamptz,timestamptz) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.complete_nvd_page(uuid,uuid,uuid,integer,integer,integer,integer,integer) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.fail_nvd_page(uuid,uuid,uuid,text,integer,jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.observe_nvd_cve_source(uuid,uuid,text,text,timestamptz,timestamptz,text) TO service_role;
GRANT EXECUTE ON FUNCTION public.claim_nvd_page(uuid,text,timestamptz,timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION public.complete_nvd_page(uuid,uuid,uuid,integer,integer,integer,integer,integer) TO service_role;
GRANT EXECUTE ON FUNCTION public.fail_nvd_page(uuid,uuid,uuid,text,integer,jsonb) TO service_role;
