# ADR 001 — Modelo de datos inicial de SOC Radar

- Estado: aprobado para revisión local; no aplicado a Supabase.
- Fecha: 2026-09-22.

## Contexto y decisión

La primera migración define 18 tablas: 17 en `public` para el catálogo y una en `internal` para auditoría futura de ingesta. No incluye datos, conectores, funciones Edge ni operaciones remotas. Las claves internas son UUID; CVE, identificadores de advisory y noticias son atributos externos separados. Las fechas de eventos usan `timestamptz`; KEV usa `date` para sus fechas de calendario.

`vendors` y `products` forman el catálogo de fabricantes. `sources` identifica quién publicó una observación, no necesariamente el fabricante del producto. `cves`, `advisories` y `news_articles` son entidades principales. Sus relaciones con productos, CVE y tags se representan en tablas puente. `ON DELETE RESTRICT` protege evidencia y catálogos; `CASCADE` solo elimina enlaces de clasificación de tags al borrar sus extremos.

## Procedencia, puntuación y priorización

`cves` conserva el registro canónico operativo, mientras `cve_sources` mantiene una observación por fuente y CVE, con identificador externo, URL y tiempos propios. No se debe reemplazar la procedencia con el último valor que llegue.

Las puntuaciones están en `cve_cvss_metrics` porque una CVE puede recibir métricas de distintas fuentes, versiones y tipos. `metric_type` admite `primary`, `secondary`, `vendor` y `other`; la unicidad es `(cve_id, source_id, version, metric_type)`. `is_primary` es una selección operacional independiente de esa clasificación, con índice único parcial que admite como máximo una métrica operacional por CVE. El valor CVSS no se copia a `cves`.

`kev_entries` es una tabla propia porque KEV es pertenencia a un catálogo con fechas, acción requerida y metadatos específicos, no una severidad CVSS ni un booleano derivado. Una CVE puede aparecer como máximo una vez en KEV. `source_id` conserva la fuente de esa inclusión.

`cve_references` guarda la fuente opcional que aportó el enlace y evita duplicados por `(cve_id, normalized_url)`. Si varias fuentes aportan la misma URL, se conserva una fila canónica; `source_id` registra la procedencia seleccionada para esa fila. Un historial de múltiples fuentes por referencia requeriría una tabla adicional en otra fase.

`cve_products` representa afirmaciones de fuente, no hechos canónicos indiscutibles. Tiene `source_id` opcional y `relationship_type` (`affected`, `fixed`, `not_affected`, `unknown`). Si falta `source_id`, se exige `evidence_url` no vacía. Un UUID permite esta procedencia opcional sin introducir `NULL` en una PK compuesta. Dos índices únicos parciales impiden duplicados tanto con fuente como sin ella; distintas fuentes o tipos pueden discrepar. El índice sin fuente permite una afirmación por pareja CVE-producto y tipo, aunque existan varias URL de evidencia; ampliar a múltiples evidencias requerirá una tabla específica.

## Publicaciones y deduplicación

`news_articles` usa `normalized_url` como deduplicación global y `(source_id, external_id)` como segunda deduplicación cuando el identificador externo existe. `advisories` conserva `title`, `summary`, `url`, `external_id`, fabricante, fuente, severidad y tiempos; no copia el contenido completo del advisory. Su identidad externa es `(source_id, external_id)`. `advisory_cves` y `advisory_products` registran enlaces independientes; no se infiere que todas sus combinaciones CVE-producto sean afectaciones confirmadas.

## Seguridad y permisos

RLS se habilita en las 18 tablas. Los permisos SQL y las políticas RLS son controles separados. `anon` y `authenticated` solo reciben `SELECT` sobre las 11 tablas necesarias para vistas iniciales: `vendors`, `products`, `sources`, `cves`, `cve_cvss_metrics`, `cve_references`, `kev_entries`, `advisories`, `advisory_cves`, `advisory_products` y `news_articles`. No reciben `INSERT`, `UPDATE` ni `DELETE` ni existen políticas de escritura para ellos.

`cves`, `advisories` y `news_articles` nacen con `is_public = false`; solo las filas publicadas deliberadamente son visibles. Las políticas de sus tablas dependientes comprueban la visibilidad de los registros padre. Las tablas de procedencia (`cve_sources`, `cve_products`), tags y sus enlaces quedan con RLS habilitado pero sin lectura pública todavía. `internal.ingestion_runs` no tiene grants ni políticas para usuarios públicos y el esquema `internal` no se expone. El rol SQL `service_role` recibe permisos explícitos para futuras operaciones confiables de servidor; esto no implica almacenar ni usar una clave API legacy. El esquema `internal` debe seguir fuera de la lista de esquemas expuestos en la Data API de Supabase.

La función de `updated_at` vive en `internal`, usa derechos de invocador y `search_path` vacío. No se concede su ejecución a roles públicos. Los triggers se aplican solo a tablas con columna `updated_at`. Los índices de PK y UNIQUE no se duplican; se añaden índices inversos para FKs de tablas puente y parciales para lecturas públicas y unicidad opcional.

## Fuera de alcance

- EPSS no se guarda en `cves` ni se crea `epss_observations` ahora. La fase futura conservará historial por `(cve_id, source_id, score_date)` con `probability` y `percentile`.
- Ingesta, normalización avanzada de URLs, resolución de conflictos entre fuentes, automatización de `is_public`, IA, inventario de clientes, correlación, autenticación, alertas y datos derivados quedan para fases posteriores.
- La migración solo se valida localmente y requiere revisión en un entorno PostgreSQL/Supabase antes de aplicarse; no se ejecuta contra el proyecto remoto en esta fase.
