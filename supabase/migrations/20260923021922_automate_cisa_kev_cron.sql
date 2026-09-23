-- Keep the Secret API Key in Vault. This migration contains only its name.
CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net;

DO $$
BEGIN
  IF (SELECT count(*) FROM vault.secrets WHERE name = 'cisa_ingestion_api_key') <> 1 THEN
    RAISE EXCEPTION 'Vault secret cisa_ingestion_api_key must exist exactly once before scheduling';
  END IF;
END;
$$;

CREATE FUNCTION internal.invoke_cisa_ingestion()
RETURNS bigint
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = ''
AS $$
DECLARE
  v_api_key text;
  v_request_id bigint;
BEGIN
  SELECT decrypted_secret INTO v_api_key
  FROM vault.decrypted_secrets
  WHERE name = 'cisa_ingestion_api_key';

  IF v_api_key IS NULL OR pg_catalog.btrim(v_api_key) = '' THEN
    RAISE EXCEPTION 'Vault secret cisa_ingestion_api_key is unavailable';
  END IF;

  SELECT net.http_post(
    url := 'https://ralvrutiuvohuuwagvcr.supabase.co/functions/v1/ingest-cisa-kev',
    body := '{}'::jsonb,
    headers := pg_catalog.jsonb_build_object(
      'Content-Type', 'application/json',
      'apikey', v_api_key
    ),
    timeout_milliseconds := 240000
  ) INTO v_request_id;

  RETURN v_request_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION internal.invoke_cisa_ingestion()
  FROM PUBLIC, anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION internal.invoke_cisa_ingestion() TO postgres;

SELECT cron.schedule(
  'soc-radar-cisa-kev',
  '*/5 * * * *',
  'SELECT internal.invoke_cisa_ingestion();'
);
