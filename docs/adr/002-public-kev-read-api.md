# ADR 002 — Lectura pública limitada de CISA KEV

## Decisión

La excepción editorial para CISA KEV se implementa mediante cuatro RPC de solo lectura en `public`: resumen, entradas paginadas, fabricantes y productos. Los registros de `cves` permanecen con `is_public = false`; no se abren permisos `SELECT` directos sobre CVE privados, `kev_entries`, `cve_products` ni `internal`.

Las funciones son `SECURITY DEFINER` exclusivamente para leer las filas CISA que RLS no expone directamente. Todas fijan `search_path`, califican tablas explícitamente, filtran en SQL `source_key = 'cisa-kev'`, carecen de SQL dinámico y devuelven columnas fijas sin UUID internos ni metadatos de ingestión. `EXECUTE` se revoca de `PUBLIC` y se concede únicamente a `anon` y `authenticated`. No se conceden permisos de escritura. La advertencia automática sobre funciones `SECURITY DEFINER` ejecutables por `anon` es conocida y deliberada para esta API acotada.

## Consumo

Next.js consulta las RPC solo desde Server Components mediante el cliente de servidor con la clave publicable. Las consultas viven en `src/features/kev`; las páginas y componentes no crean clientes ni llaman RPC directamente. El dashboard muestra datos reales CISA KEV para total, añadidos en los últimos siete días calendario, prioridad, fabricantes, productos y ransomware. La página `/kev` pagina de 25 en 25. CVSS, severidad, advisories y noticias siguen etiquetados como `DEMO` hasta incorporar fuentes verificadas.

El valor `NULL` de `known_ransomware_campaign_use` se conserva como «No indicado»; no equivale a `false`. La actualización usa `router.refresh()` cada cinco minutos, sin polling adicional. Los fallos de lectura no se convierten en valores mock aparentando ser datos reales.

## Security Advisor findings

Las cuatro RPC públicas de CISA KEV usan `SECURITY DEFINER` deliberadamente para ofrecer una proyección de solo lectura de filas que RLS impide consultar directamente. `anon` y `authenticated` tienen `EXECUTE` explícito porque son los consumidores de esta API pública limitada; `PUBLIC` no tiene `EXECUTE`.

El contrato de seguridad exige `search_path` fijo, referencias de esquema explícitas, ausencia de SQL dinámico y ausencia de escrituras. Ninguna función acepta `source_id`, nombres de tablas o esquemas ni SQL arbitrario; todas fijan internamente `source_key = 'cisa-kev'`. Sus columnas de salida son fijas y no incluyen UUID internos, metadatos de ingestión, datos de `internal` ni secretos. Cualquier ampliación del contrato requiere una nueva revisión de seguridad.

RLS y los permisos de lectura directa permanecen intactos: `anon` no ve CVE privados ni `kev_entries` directamente, y `cve_products` no es público. En la revisión del 23 de septiembre de 2026, los 1721 CVE tenían `is_public = false`; `anon` obtuvo cero filas de `cves` y `kev_entries` directamente, pero sí pudo consultar las entradas CISA KEV previstas mediante las RPC.

Se aceptan explícitamente los avisos [0028 — ejecución anónima de `SECURITY DEFINER`](https://supabase.com/docs/guides/observability/advisors?queryGroups=lint&lint=0028_anon_security_definer_function_executable) y [0029 — ejecución por usuarios autenticados de `SECURITY DEFINER`](https://supabase.com/docs/guides/observability/advisors?queryGroups=lint&lint=0029_authenticated_security_definer_function_executable) para estas cuatro funciones mientras su contrato público no se amplíe. Son avisos de una capacidad privilegiada real, no una garantía de ausencia de riesgo.

El riesgo residual principal es el abuso de consultas y paginación. `p_limit` se valida entre 1 y 100, pero `p_offset` solo exige ser no negativo y no tiene máximo explícito. Los `statement_timeout` configurados para los roles `anon` (3 s) y `authenticated` (8 s) son una mitigación parcial, no un control de tasa ni un límite de costo por consulta. Si el volumen o el abuso lo justifican, evaluar paginación por cursor y rate limiting.

El aviso [0014 — extensión en `public`](https://supabase.com/docs/guides/observability/advisors?queryGroups=lint&lint=0014_extension_in_public) para `pg_net` queda pendiente de una revisión de hardening separada. No mover ni reinstalar ahora la extensión: antes deben revisarse los permisos del esquema `net` y las dependencias del Cron CISA.

## Consecuencias

Cada nuevo campo público requerirá una revisión explícita del contrato de las RPC y de sus permisos. La API no permite cambiar la fuente desde el cliente ni consultar el catálogo CVE privado general. La publicación editorial completa de CVE queda para una fase posterior.
