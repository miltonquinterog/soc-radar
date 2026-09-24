-- Qualify table columns that conflict with RETURNS TABLE output parameters.
-- Signature, behavior, and existing EXECUTE privileges remain unchanged.
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
  SELECT * INTO v_state FROM internal.collector_state AS cs WHERE cs.id = p_state_id FOR UPDATE;
  IF NOT FOUND OR v_state.status <> 'running' OR v_state.active_run_id <> p_run_id
    OR v_state.lease_token <> p_lease_token OR v_state.lease_expires_at <= clock_timestamp()
  THEN RAISE EXCEPTION 'NVD page lease invalid or expired' USING ERRCODE = 'P0002'; END IF;
  v_next := v_state.next_start_index + p_page_count;
  IF v_next > p_total_results OR (p_page_count = 0 AND v_state.next_start_index < p_total_results)
  THEN RAISE EXCEPTION 'inconsistent NVD pagination' USING ERRCODE = '22023'; END IF;
  v_done := v_next >= p_total_results;
  UPDATE internal.ingestion_runs AS ir SET status = 'succeeded', finished_at = clock_timestamp(),
    records_found = p_page_count, records_inserted = p_inserted,
    records_updated = p_updated, records_skipped = p_skipped,
    batches_total = 1, batches_completed = 1, next_batch_number = 1,
    details = ir.details || jsonb_build_object('total_results', p_total_results)
  WHERE ir.id = p_run_id AND ir.status = 'running';
  IF NOT FOUND THEN RAISE EXCEPTION 'running NVD run missing' USING ERRCODE = 'P0002'; END IF;
  UPDATE internal.collector_state AS cs SET next_start_index = v_next,
    status = CASE WHEN v_done THEN 'completed' ELSE 'running' END,
    high_water_mark = CASE WHEN v_done AND cs.mode = 'incremental' THEN cs.window_end ELSE cs.high_water_mark END,
    lease_token = NULL, lease_expires_at = NULL, active_run_id = NULL, page_attempts = 0
  WHERE cs.id = p_state_id;
  RETURN QUERY SELECT CASE WHEN v_done THEN 'completed' ELSE 'running' END, v_next;
END;
$$;
