# ADR 002 — Lectura pública limitada de CISA KEV

## Decisión

La excepción editorial para CISA KEV se implementa mediante cuatro RPC de solo lectura en `public`: resumen, entradas paginadas, fabricantes y productos. Los registros de `cves` permanecen con `is_public = false`; no se abren permisos `SELECT` directos sobre CVE privados, `kev_entries`, `cve_products` ni `internal`.

Las funciones son `SECURITY DEFINER` exclusivamente para leer las filas CISA que RLS no expone directamente. Todas fijan `search_path`, califican tablas explícitamente, filtran en SQL `source_key = 'cisa-kev'`, carecen de SQL dinámico y devuelven columnas fijas sin UUID internos ni metadatos de ingestión. `EXECUTE` se revoca de `PUBLIC` y se concede únicamente a `anon` y `authenticated`. No se conceden permisos de escritura. La advertencia automática sobre funciones `SECURITY DEFINER` ejecutables por `anon` es conocida y deliberada para esta API acotada.

## Consumo

Next.js consulta las RPC solo desde Server Components mediante el cliente de servidor con la clave publicable. Las consultas viven en `src/features/kev`; las páginas y componentes no crean clientes ni llaman RPC directamente. El dashboard muestra datos reales CISA KEV para total, añadidos en los últimos siete días calendario, prioridad, fabricantes, productos y ransomware. La página `/kev` pagina de 25 en 25. CVSS, severidad, advisories y noticias siguen etiquetados como `DEMO` hasta incorporar fuentes verificadas.

El valor `NULL` de `known_ransomware_campaign_use` se conserva como «No indicado»; no equivale a `false`. La actualización usa `router.refresh()` cada cinco minutos, sin polling adicional. Los fallos de lectura no se convierten en valores mock aparentando ser datos reales.

## Consecuencias

Cada nuevo campo público requerirá una revisión explícita del contrato de las RPC y de sus permisos. La API no permite cambiar la fuente desde el cliente ni consultar el catálogo CVE privado general. La publicación editorial completa de CVE queda para una fase posterior.
