-- SOC Radar: initial catalogue schema. No data or remote resources are created.
CREATE SCHEMA IF NOT EXISTS internal;

CREATE FUNCTION internal.set_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = '' AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TABLE public.vendors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  name text NOT NULL CHECK (btrim(name) <> ''),
  website_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_id uuid NOT NULL REFERENCES public.vendors(id) ON DELETE RESTRICT,
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  name text NOT NULL CHECK (btrim(name) <> ''),
  product_family text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vendor_id, slug)
);
CREATE TABLE public.sources (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_key text NOT NULL UNIQUE CHECK (source_key ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  name text NOT NULL CHECK (btrim(name) <> ''),
  source_type text NOT NULL CHECK (source_type IN
    ('government', 'vendor', 'vulnerability_database', 'threat_intelligence', 'news', 'research')),
  vendor_id uuid REFERENCES public.vendors(id) ON DELETE RESTRICT,
  base_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.cves (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id text NOT NULL UNIQUE CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  status text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'reserved', 'published', 'rejected')),
  description text,
  description_source_id uuid REFERENCES public.sources(id) ON DELETE RESTRICT,
  published_at timestamptz,
  last_modified_at timestamptz,
  is_public boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (last_modified_at IS NULL OR published_at IS NULL OR last_modified_at >= published_at)
);
CREATE TABLE public.cve_sources (
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE RESTRICT,
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  source_record_id text,
  source_url text,
  source_published_at timestamptz,
  source_updated_at timestamptz,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, source_id),
  CHECK (last_seen_at >= first_seen_at)
);
CREATE TABLE public.cve_cvss_metrics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE RESTRICT,
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  version text NOT NULL CHECK (version IN ('2.0', '3.0', '3.1', '4.0')),
  metric_type text NOT NULL DEFAULT 'primary' CHECK (metric_type IN ('primary', 'secondary', 'vendor', 'other')),
  base_score numeric(3,1) NOT NULL CHECK (base_score BETWEEN 0 AND 10),
  vector text,
  is_primary boolean NOT NULL DEFAULT false,
  source_updated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cve_id, source_id, version, metric_type)
);
CREATE TABLE public.cve_references (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE RESTRICT,
  source_id uuid REFERENCES public.sources(id) ON DELETE RESTRICT,
  url text NOT NULL CHECK (btrim(url) <> ''),
  normalized_url text NOT NULL CHECK (btrim(normalized_url) <> ''),
  reference_type text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cve_id, normalized_url)
);
CREATE TABLE public.cve_products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE RESTRICT,
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
  source_id uuid REFERENCES public.sources(id) ON DELETE RESTRICT,
  evidence_url text,
  relationship_type text NOT NULL DEFAULT 'affected'
    CHECK (relationship_type IN ('affected', 'fixed', 'not_affected', 'unknown')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (source_id IS NOT NULL OR (evidence_url IS NOT NULL AND btrim(evidence_url) <> '')),
  CHECK (evidence_url IS NULL OR btrim(evidence_url) <> '')
);
CREATE TABLE public.kev_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id uuid NOT NULL UNIQUE REFERENCES public.cves(id) ON DELETE RESTRICT,
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  date_added date NOT NULL,
  due_date date,
  required_action text NOT NULL CHECK (btrim(required_action) <> ''),
  known_ransomware_campaign_use boolean,
  notes text,
  source_vendor_name text,
  source_product_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (due_date IS NULL OR due_date >= date_added)
);
CREATE TABLE public.advisories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_id uuid NOT NULL REFERENCES public.vendors(id) ON DELETE RESTRICT,
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  external_id text NOT NULL CHECK (btrim(external_id) <> ''),
  title text NOT NULL CHECK (btrim(title) <> ''),
  summary text,
  url text NOT NULL CHECK (btrim(url) <> ''),
  severity text CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
  published_at timestamptz,
  source_updated_at timestamptz,
  is_public boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id, external_id)
);
CREATE TABLE public.advisory_cves (
  advisory_id uuid NOT NULL REFERENCES public.advisories(id) ON DELETE RESTRICT,
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (advisory_id, cve_id)
);
CREATE TABLE public.advisory_products (
  advisory_id uuid NOT NULL REFERENCES public.advisories(id) ON DELETE RESTRICT,
  product_id uuid NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (advisory_id, product_id)
);
CREATE TABLE public.news_articles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  external_id text CHECK (external_id IS NULL OR btrim(external_id) <> ''),
  title text NOT NULL CHECK (btrim(title) <> ''),
  url text NOT NULL CHECK (btrim(url) <> ''),
  normalized_url text NOT NULL UNIQUE CHECK (btrim(normalized_url) <> ''),
  canonical_url text,
  author text,
  summary text,
  image_url text,
  published_at timestamptz,
  is_public boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.tags (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  label text NOT NULL CHECK (btrim(label) <> ''),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.cve_tags (
  cve_id uuid NOT NULL REFERENCES public.cves(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (cve_id, tag_id)
);
CREATE TABLE public.advisory_tags (
  advisory_id uuid NOT NULL REFERENCES public.advisories(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (advisory_id, tag_id)
);
CREATE TABLE public.news_tags (
  news_article_id uuid NOT NULL REFERENCES public.news_articles(id) ON DELETE CASCADE,
  tag_id uuid NOT NULL REFERENCES public.tags(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (news_article_id, tag_id)
);
CREATE TABLE internal.ingestion_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id uuid NOT NULL REFERENCES public.sources(id) ON DELETE RESTRICT,
  collector_type text NOT NULL CHECK (btrim(collector_type) <> ''),
  status text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'partial', 'failed')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  records_found integer NOT NULL DEFAULT 0 CHECK (records_found >= 0),
  records_inserted integer NOT NULL DEFAULT 0 CHECK (records_inserted >= 0),
  records_updated integer NOT NULL DEFAULT 0 CHECK (records_updated >= 0),
  records_skipped integer NOT NULL DEFAULT 0 CHECK (records_skipped >= 0),
  error_count integer NOT NULL DEFAULT 0 CHECK (error_count >= 0),
  error_message text,
  CHECK (finished_at IS NULL OR finished_at >= started_at),
  CHECK ((status = 'running' AND finished_at IS NULL)
    OR (status <> 'running' AND finished_at IS NOT NULL))
);

-- PK and UNIQUE constraints already provide their own B-tree indexes.
CREATE INDEX sources_vendor_id_idx ON public.sources (vendor_id) WHERE vendor_id IS NOT NULL;
CREATE INDEX cves_description_source_id_idx ON public.cves (description_source_id)
  WHERE description_source_id IS NOT NULL;
CREATE INDEX cves_public_published_at_idx ON public.cves (published_at DESC, id) WHERE is_public;
CREATE INDEX cves_public_last_modified_at_idx ON public.cves (last_modified_at DESC, id) WHERE is_public;
CREATE INDEX cve_sources_source_id_cve_id_idx ON public.cve_sources (source_id, cve_id);
CREATE UNIQUE INDEX cve_cvss_metrics_operational_primary_idx
  ON public.cve_cvss_metrics (cve_id) WHERE is_primary;
CREATE INDEX cve_cvss_metrics_primary_score_idx
  ON public.cve_cvss_metrics (base_score DESC, cve_id) WHERE is_primary;
CREATE INDEX cve_cvss_metrics_source_id_idx ON public.cve_cvss_metrics (source_id);
CREATE INDEX cve_references_source_id_idx ON public.cve_references (source_id)
  WHERE source_id IS NOT NULL;
CREATE UNIQUE INDEX cve_products_sourced_unique_idx
  ON public.cve_products (cve_id, product_id, source_id, relationship_type)
  WHERE source_id IS NOT NULL;
CREATE UNIQUE INDEX cve_products_unsourced_unique_idx
  ON public.cve_products (cve_id, product_id, relationship_type)
  WHERE source_id IS NULL;
CREATE INDEX cve_products_product_relationship_idx
  ON public.cve_products (product_id, relationship_type, cve_id);
CREATE INDEX cve_products_source_id_idx ON public.cve_products (source_id)
  WHERE source_id IS NOT NULL;
CREATE INDEX kev_entries_date_added_idx ON public.kev_entries (date_added DESC, cve_id);
CREATE INDEX kev_entries_due_date_idx ON public.kev_entries (due_date) WHERE due_date IS NOT NULL;
CREATE INDEX kev_entries_source_id_idx ON public.kev_entries (source_id);
CREATE INDEX advisories_vendor_published_at_idx ON public.advisories (vendor_id, published_at DESC);
CREATE INDEX advisories_public_published_at_idx ON public.advisories (published_at DESC, id) WHERE is_public;
CREATE INDEX advisories_public_severity_published_at_idx
  ON public.advisories (severity, published_at DESC) WHERE is_public;
CREATE INDEX advisory_cves_cve_id_advisory_id_idx ON public.advisory_cves (cve_id, advisory_id);
CREATE INDEX advisory_products_product_id_advisory_id_idx
  ON public.advisory_products (product_id, advisory_id);
CREATE UNIQUE INDEX news_articles_source_external_id_idx
  ON public.news_articles (source_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX news_articles_public_published_at_idx
  ON public.news_articles (published_at DESC, id) WHERE is_public;
CREATE INDEX news_articles_source_published_at_idx
  ON public.news_articles (source_id, published_at DESC);
CREATE INDEX cve_tags_tag_id_cve_id_idx ON public.cve_tags (tag_id, cve_id);
CREATE INDEX advisory_tags_tag_id_advisory_id_idx ON public.advisory_tags (tag_id, advisory_id);
CREATE INDEX news_tags_tag_id_news_article_id_idx ON public.news_tags (tag_id, news_article_id);
CREATE INDEX ingestion_runs_source_started_at_idx ON internal.ingestion_runs (source_id, started_at DESC);
CREATE INDEX ingestion_runs_status_started_at_idx ON internal.ingestion_runs (status, started_at DESC);

-- One invoker-rights trigger function for mutable records only.
CREATE TRIGGER vendors_updated_at BEFORE UPDATE ON public.vendors
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER products_updated_at BEFORE UPDATE ON public.products
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER sources_updated_at BEFORE UPDATE ON public.sources
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER cves_updated_at BEFORE UPDATE ON public.cves
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER cve_cvss_metrics_updated_at BEFORE UPDATE ON public.cve_cvss_metrics
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER cve_products_updated_at BEFORE UPDATE ON public.cve_products
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER kev_entries_updated_at BEFORE UPDATE ON public.kev_entries
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER advisories_updated_at BEFORE UPDATE ON public.advisories
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER news_articles_updated_at BEFORE UPDATE ON public.news_articles
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();
CREATE TRIGGER tags_updated_at BEFORE UPDATE ON public.tags
  FOR EACH ROW EXECUTE FUNCTION internal.set_updated_at();

-- RLS and SQL grants are separate controls. No public write grants or policies.
ALTER TABLE public.vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_cvss_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kev_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.advisory_cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.advisory_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.news_articles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cve_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.advisory_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.news_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal.ingestion_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY vendors_read ON public.vendors FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY products_read ON public.products FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY sources_read ON public.sources FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY cves_read ON public.cves FOR SELECT TO anon, authenticated USING (is_public);
CREATE POLICY cve_cvss_metrics_read ON public.cve_cvss_metrics FOR SELECT TO anon, authenticated
  USING (EXISTS (
    SELECT 1 FROM public.cves AS c
    WHERE c.id = cve_cvss_metrics.cve_id AND c.is_public
  ));
CREATE POLICY cve_references_read ON public.cve_references FOR SELECT TO anon, authenticated
  USING (EXISTS (
    SELECT 1 FROM public.cves AS c
    WHERE c.id = cve_references.cve_id AND c.is_public
  ));
CREATE POLICY kev_entries_read ON public.kev_entries FOR SELECT TO anon, authenticated
  USING (EXISTS (
    SELECT 1 FROM public.cves AS c
    WHERE c.id = kev_entries.cve_id AND c.is_public
  ));
CREATE POLICY advisories_read ON public.advisories FOR SELECT TO anon, authenticated USING (is_public);
CREATE POLICY advisory_cves_read ON public.advisory_cves FOR SELECT TO anon, authenticated
  USING (
    EXISTS (SELECT 1 FROM public.advisories AS a
      WHERE a.id = advisory_cves.advisory_id AND a.is_public)
    AND EXISTS (SELECT 1 FROM public.cves AS c
      WHERE c.id = advisory_cves.cve_id AND c.is_public)
  );
CREATE POLICY advisory_products_read ON public.advisory_products FOR SELECT TO anon, authenticated
  USING (EXISTS (
    SELECT 1 FROM public.advisories AS a
    WHERE a.id = advisory_products.advisory_id AND a.is_public
  ));
CREATE POLICY news_articles_read ON public.news_articles FOR SELECT TO anon, authenticated USING (is_public);

REVOKE ALL ON SCHEMA internal FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA internal TO service_role;
REVOKE ALL ON FUNCTION internal.set_updated_at() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION internal.set_updated_at() TO service_role;

REVOKE ALL ON TABLE
  public.vendors, public.products, public.sources, public.cves,
  public.cve_sources, public.cve_cvss_metrics, public.cve_references,
  public.cve_products, public.kev_entries, public.advisories,
  public.advisory_cves, public.advisory_products, public.news_articles,
  public.tags, public.cve_tags, public.advisory_tags, public.news_tags,
  internal.ingestion_runs
FROM PUBLIC, anon, authenticated;
GRANT SELECT ON TABLE
  public.vendors, public.products, public.sources, public.cves,
  public.cve_cvss_metrics, public.cve_references, public.kev_entries,
  public.advisories, public.advisory_cves, public.advisory_products,
  public.news_articles
TO anon, authenticated;
-- service_role is a database role, not an API key. Only trusted server-side
-- processes may use credentials associated with it in future phases.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.vendors, public.products, public.sources, public.cves,
  public.cve_sources, public.cve_cvss_metrics, public.cve_references,
  public.cve_products, public.kev_entries, public.advisories,
  public.advisory_cves, public.advisory_products, public.news_articles,
  public.tags, public.cve_tags, public.advisory_tags, public.news_tags,
  internal.ingestion_runs
TO service_role;
