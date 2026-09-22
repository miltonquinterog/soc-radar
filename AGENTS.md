# SOC Radar — Reglas de arquitectura y desarrollo

## Alcance de la primera fase

- Construir una aplicación informativa de ciberseguridad con Next.js, TypeScript, Tailwind CSS y Supabase.
- La primera entrega prioriza el modelo de datos, las pantallas de consulta y datos de ejemplo controlados.
- No implementar aún conectores, scraping, APIs de terceros, jobs de ingesta, IA, alertas, inventario de clientes ni integración con Stellar Cyber.
- No incorporar FastAPI, Redis, Celery, VPS ni servicios de infraestructura alternativos.

## Stack aprobado

- Frontend y capa de aplicación: Next.js (App Router) + TypeScript estricto.
- Estilos: Tailwind CSS; componentes reutilizables y accesibles.
- Datos, autenticación futura, tareas programadas y funciones: Supabase (PostgreSQL, Auth, Edge Functions y Cron).
- Hosting: Vercel.
- Control de versiones: GitHub.

## Variables de entorno de Supabase

- Usar las claves actuales de Supabase, no las claves legacy `anon` ni `service_role`.
- Código de navegador: `NEXT_PUBLIC_SUPABASE_URL` y `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` únicamente.
- Operaciones exclusivamente de servidor futuras: `SUPABASE_URL` y `SUPABASE_SECRET_KEY` únicamente.
- `SUPABASE_SECRET_KEY` nunca puede importarse, serializarse ni exponerse a componentes cliente.
- Las claves no se hardcodean. `.env.local` debe permanecer ignorado por Git y `.env.example` solo declara nombres de variables vacíos.

## Principios de diseño

- Mantener una arquitectura modular, con límites claros entre interfaz, dominio y acceso a datos.
- Usar Server Components por defecto. Usar Client Components únicamente cuando haya interactividad o APIs del navegador.
- Centralizar acceso a Supabase en módulos de `src/lib/supabase`; no instanciar clientes ad hoc en páginas o componentes.
- Validar entradas y respuestas de frontera con esquemas tipados (por ejemplo, Zod cuando se introduzca la necesidad).
- Tratar CVE, KEV, advisories, fuentes y relaciones como datos normalizados. Conservar el payload original de una fuente solo cuando aporte trazabilidad.
- Añadir migraciones SQL versionadas para cada cambio de esquema; nunca editar manualmente producción sin una migración revisable.
- Aplicar RLS desde el inicio a tablas expuestas por Supabase. Las operaciones con `SUPABASE_SECRET_KEY` solo pueden ejecutarse del lado servidor o en Edge Functions y jamás se exponen al navegador.
- Diseñar para múltiples clientes, pero no crear todavía lógica de correlación ni inventario.

## Convenciones de datos

- Usar UUID como clave primaria, `timestamptz` en UTC para fechas y `created_at`/`updated_at` cuando corresponda.
- Usar `snake_case` en PostgreSQL y `camelCase` en TypeScript cuando sea natural para el código.
- Evitar enums de PostgreSQL para taxonomías que puedan evolucionar con frecuencia; preferir tablas de referencia o restricciones `check` justificadas.
- Mantener identificadores canónicos: CVE como `CVE-YYYY-NNNN...`, advisory por `source_id + external_id` y fabricante como entidad separada.
- Los registros importados deben conservar `source_id`, URL de origen, fecha de publicación y fecha de última modificación.

## Organización del código

- Rutas y layouts en `src/app`.
- Componentes de interfaz reutilizables en `src/components/ui`.
- Componentes de dominio en `src/components/<dominio>`.
- Casos de uso y consultas en `src/features/<dominio>`.
- Utilidades, configuración y clientes externos en `src/lib`.
- Tipos compartidos en `src/types`.
- Migraciones y configuración de Supabase en `supabase/`.
- No mezclar consultas SQL, llamadas de red y presentación visual en el mismo componente.

## Calidad y seguridad

- No incluir secretos, tokens, URLs privadas ni archivos `.env*` en Git.
- Mantener `.env.example` con nombres de variables y valores ficticios.
- No usar `NEXT_PUBLIC_` salvo para valores seguros que deban llegar al navegador.
- Toda nueva vista debe contemplar carga, vacío, error, responsive y accesibilidad básica.
- No añadir dependencias sin una razón concreta; preferir las capacidades nativas del stack.
- Antes de abrir un PR, ejecutar formateo, lint, comprobación de tipos, pruebas disponibles y build cuando el entorno lo permita.
- Documentar decisiones arquitectónicas relevantes en `docs/adr/` cuando se aparten de estas reglas.

## Evolución posterior

- La ingesta se implementará con Edge Functions y Supabase Cron, usando adaptadores por fuente y ejecuciones auditables.
- La IA debe operar sobre datos persistidos y trazables; sus resultados se almacenarán separadamente del contenido fuente.
- Inventario de tecnologías, clientes, correlación, Stellar Cyber e informes vivirán en módulos de dominio independientes y no deben acoplar el catálogo público de vulnerabilidades.
- Alertas por Teams/email se activarán mediante reglas y eventos, no desde componentes del frontend.
