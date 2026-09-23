ALTER TABLE internal.ingestion_runs
  ADD COLUMN source_catalog_version text,
  ADD COLUMN source_released_at timestamptz,
  ADD COLUMN source_payload_hash text,
  ADD COLUMN details jsonb;

ALTER TABLE public.kev_entries
  ADD COLUMN source_vulnerability_name text;
