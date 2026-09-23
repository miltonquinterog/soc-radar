CREATE OR REPLACE FUNCTION public.create_ingestion_run(
  p_source_id uuid,
  p_collector_type text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_run_id uuid;
BEGIN
  IF p_source_id IS NULL THEN
    RAISE EXCEPTION 'source_id is required' USING ERRCODE = '22023';
  END IF;
  IF p_collector_type IS NULL
    OR btrim(p_collector_type) = ''
    OR char_length(btrim(p_collector_type)) > 100 THEN
    RAISE EXCEPTION 'collector_type must be between 1 and 100 characters' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.sources WHERE id = p_source_id) THEN
    RAISE EXCEPTION 'source_id does not exist' USING ERRCODE = '23503';
  END IF;

  INSERT INTO internal.ingestion_runs (source_id, collector_type, status)
  VALUES (p_source_id, btrim(p_collector_type), 'running')
  RETURNING id INTO v_run_id;

  RETURN v_run_id;
END;
$$;

CREATE OR REPLACE FUNCTION public.update_ingestion_run_metadata(
  p_run_id uuid,
  p_source_catalog_version text,
  p_source_released_at timestamptz,
  p_source_payload_hash text,
  p_records_found integer,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
  IF p_run_id IS NULL
    OR p_source_catalog_version IS NULL
    OR btrim(p_source_catalog_version) = ''
    OR char_length(btrim(p_source_catalog_version)) > 200
    OR p_source_released_at IS NULL
    OR p_source_payload_hash IS NULL
    OR p_source_payload_hash !~* '^[0-9a-f]{64}$'
    OR p_records_found IS NULL
    OR p_records_found < 0
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion metadata arguments' USING ERRCODE = '22023';
  END IF;

  UPDATE internal.ingestion_runs
  SET source_catalog_version = btrim(p_source_catalog_version),
      source_released_at = p_source_released_at,
      source_payload_hash = lower(p_source_payload_hash),
      records_found = p_records_found,
      details = COALESCE(details, '{}'::jsonb) || v_details
  WHERE id = p_run_id
    AND status = 'running';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'running ingestion run not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.finish_ingestion_run(
  p_run_id uuid,
  p_status text,
  p_finished_at timestamptz,
  p_records_found integer,
  p_records_inserted integer,
  p_records_updated integer,
  p_records_skipped integer,
  p_error_count integer,
  p_error_message text,
  p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_details jsonb := COALESCE(p_details, '{}'::jsonb);
BEGIN
  IF p_run_id IS NULL
    OR p_status NOT IN ('succeeded', 'partial', 'failed')
    OR p_finished_at IS NULL
    OR p_records_found IS NULL OR p_records_found < 0
    OR p_records_inserted IS NULL OR p_records_inserted < 0
    OR p_records_updated IS NULL OR p_records_updated < 0
    OR p_records_skipped IS NULL OR p_records_skipped < 0
    OR p_error_count IS NULL OR p_error_count < 0
    OR (p_error_message IS NOT NULL AND char_length(p_error_message) > 4000)
    OR jsonb_typeof(v_details) <> 'object' THEN
    RAISE EXCEPTION 'invalid ingestion run completion arguments' USING ERRCODE = '22023';
  END IF;

  UPDATE internal.ingestion_runs
  SET status = p_status,
      finished_at = p_finished_at,
      records_found = p_records_found,
      records_inserted = p_records_inserted,
      records_updated = p_records_updated,
      records_skipped = p_records_skipped,
      error_count = p_error_count,
      error_message = p_error_message,
      details = COALESCE(details, '{}'::jsonb) || v_details
  WHERE id = p_run_id
    AND status = 'running';

  IF NOT FOUND THEN
    RAISE EXCEPTION 'running ingestion run not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.create_ingestion_run(uuid, text)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.update_ingestion_run_metadata(uuid, text, timestamptz, text, integer, jsonb)
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.finish_ingestion_run(
  uuid, text, timestamptz, integer, integer, integer, integer, integer, text, jsonb
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.create_ingestion_run(uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.update_ingestion_run_metadata(uuid, text, timestamptz, text, integer, jsonb)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.finish_ingestion_run(
  uuid, text, timestamptz, integer, integer, integer, integer, integer, text, jsonb
) TO service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated;
