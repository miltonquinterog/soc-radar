-- Prepare NVD provenance and durable checkpoints. No NVD records are inserted.
-- This migration deliberately defers CWE, CPE/configurations, version ranges,
-- and multi-source reference attribution (cve_reference_sources).

-- No contributor can be inferred safely for a pre-existing metric. Stop instead
-- of assigning a fabricated identifier if data appears before deployment.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.cve_cvss_metrics LIMIT 1) THEN
    RAISE EXCEPTION 'cve_cvss_metrics is not empty; backfill metric_source_identifier from its original provenance before applying this migration';
  END IF;
END;
$$;

ALTER TABLE public.cve_cvss_metrics
  ADD COLUMN metric_source_identifier text NOT NULL,
  ADD CONSTRAINT cve_cvss_metrics_metric_source_identifier_check
    CHECK (btrim(metric_source_identifier) <> ''),
  DROP CONSTRAINT cve_cvss_metrics_cve_id_source_id_version_metric_type_key,
  ADD CONSTRAINT cve_cvss_metrics_contributor_unique
    UNIQUE (cve_id, source_id, version, metric_type, metric_source_identifier);

-- Keep the exact upstream status, independently of public.cves.status.
ALTER TABLE public.cve_sources
  ADD COLUMN source_status text,
  ADD CONSTRAINT cve_sources_source_status_check
    CHECK (source_status IS NULL OR btrim(source_status) <> '');

-- A checkpoint is durable collector state, not an ingestion-run audit record.
CREATE TABLE internal.collector_state (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  collector_type text NOT NULL CHECK (btrim(collector_type) <> ''),
  mode text NOT NULL CHECK (mode IN ('bootstrap', 'incremental')),
  status text NOT NULL DEFAULT 'idle'
    CHECK (status IN ('idle', 'running', 'failed', 'completed')),
  window_start timestamptz,
  window_end timestamptz,
  next_start_index integer NOT NULL DEFAULT 0 CHECK (next_start_index >= 0),
  high_water_mark timestamptz,
  overlap_hours integer NOT NULL DEFAULT 24 CHECK (overlap_hours >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT collector_state_window_pair_check CHECK (
    (window_start IS NULL AND window_end IS NULL)
    OR (window_start IS NOT NULL AND window_end IS NOT NULL AND window_end > window_start)
  ),
  CONSTRAINT collector_state_source_collector_mode_key
    UNIQUE (source_id, collector_type, mode)
);

-- Prevent bootstrap and incremental from running concurrently for one collector.
CREATE UNIQUE INDEX collector_state_one_running_collector_idx
  ON internal.collector_state (source_id, collector_type)
  WHERE status = 'running';

CREATE TRIGGER collector_state_updated_at
  BEFORE UPDATE ON internal.collector_state
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();

-- Internal is not an exposed Data API schema. RLS and grants are independent.
ALTER TABLE internal.collector_state ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE internal.collector_state FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE internal.collector_state TO service_role;
