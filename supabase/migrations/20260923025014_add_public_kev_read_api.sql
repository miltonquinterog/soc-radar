-- Editorial exception: expose only the CISA KEV fields listed below.
-- Canonical CVEs remain private; these fixed SECURITY DEFINER functions
-- intentionally bypass their direct-read RLS policy for this narrow projection.

CREATE FUNCTION public.get_public_kev_dashboard()
RETURNS TABLE (
  total_kev bigint,
  added_last_7_days bigint,
  known_ransomware_count bigint,
  unknown_ransomware_count bigint,
  latest_date_added date,
  total_vendors bigint,
  total_products bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    count(*) AS total_kev,
    count(*) FILTER (WHERE k.date_added >= CURRENT_DATE - 6) AS added_last_7_days,
    count(*) FILTER (WHERE k.known_ransomware_campaign_use IS TRUE) AS known_ransomware_count,
    count(*) FILTER (WHERE k.known_ransomware_campaign_use IS NULL) AS unknown_ransomware_count,
    max(k.date_added) AS latest_date_added,
    count(DISTINCT nullif(pg_catalog.btrim(k.source_vendor_name), '')) AS total_vendors,
    count(DISTINCT (k.source_vendor_name, k.source_product_name))
      FILTER (
        WHERE nullif(pg_catalog.btrim(k.source_vendor_name), '') IS NOT NULL
          AND nullif(pg_catalog.btrim(k.source_product_name), '') IS NOT NULL
      ) AS total_products
  FROM public.kev_entries AS k
  JOIN public.sources AS s ON s.id = k.source_id
  WHERE s.source_key = 'cisa-kev';
$$;

REVOKE EXECUTE ON FUNCTION public.get_public_kev_dashboard()
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_public_kev_dashboard()
  TO anon, authenticated;

CREATE FUNCTION public.get_public_kev_entries(
  p_limit integer DEFAULT 25,
  p_offset integer DEFAULT 0
)
RETURNS TABLE (
  cve_id text,
  source_vendor_name text,
  source_product_name text,
  source_vulnerability_name text,
  date_added date,
  due_date date,
  required_action text,
  known_ransomware_campaign_use boolean
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'p_limit must be between 1 and 100' USING ERRCODE = '22023';
  END IF;
  IF p_offset IS NULL OR p_offset < 0 THEN
    RAISE EXCEPTION 'p_offset must be nonnegative' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT
    c.cve_id,
    k.source_vendor_name,
    k.source_product_name,
    k.source_vulnerability_name,
    k.date_added,
    k.due_date,
    k.required_action,
    k.known_ransomware_campaign_use
  FROM public.kev_entries AS k
  JOIN public.sources AS s ON s.id = k.source_id
  JOIN public.cves AS c ON c.id = k.cve_id
  WHERE s.source_key = 'cisa-kev'
  ORDER BY k.date_added DESC, c.cve_id DESC
  LIMIT p_limit OFFSET p_offset;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_public_kev_entries(integer, integer)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_public_kev_entries(integer, integer)
  TO anon, authenticated;

CREATE FUNCTION public.get_public_kev_vendors(p_limit integer DEFAULT 10)
RETURNS TABLE (vendor_name text, kev_count bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'p_limit must be between 1 and 100' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT k.source_vendor_name, count(*)
  FROM public.kev_entries AS k
  JOIN public.sources AS s ON s.id = k.source_id
  WHERE s.source_key = 'cisa-kev'
    AND nullif(pg_catalog.btrim(k.source_vendor_name), '') IS NOT NULL
  GROUP BY k.source_vendor_name
  ORDER BY count(*) DESC, k.source_vendor_name ASC
  LIMIT p_limit;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_public_kev_vendors(integer)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_public_kev_vendors(integer)
  TO anon, authenticated;

CREATE FUNCTION public.get_public_kev_products(p_limit integer DEFAULT 10)
RETURNS TABLE (vendor_name text, product_name text, kev_count bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'p_limit must be between 1 and 100' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT k.source_vendor_name, k.source_product_name, count(*)
  FROM public.kev_entries AS k
  JOIN public.sources AS s ON s.id = k.source_id
  WHERE s.source_key = 'cisa-kev'
    AND nullif(pg_catalog.btrim(k.source_vendor_name), '') IS NOT NULL
    AND nullif(pg_catalog.btrim(k.source_product_name), '') IS NOT NULL
  GROUP BY k.source_vendor_name, k.source_product_name
  ORDER BY count(*) DESC, k.source_vendor_name ASC, k.source_product_name ASC
  LIMIT p_limit;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.get_public_kev_products(integer)
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.get_public_kev_products(integer)
  TO anon, authenticated;
