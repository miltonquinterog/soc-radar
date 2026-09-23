"use client";

export default function Error({ reset }: { error: Error; reset: () => void }) {
  return <section className="kev-state" role="alert">
    <h1>No se pudo cargar CISA KEV</h1>
    <p>Los datos públicos no están disponibles en este momento.</p>
    <button type="button" onClick={reset}>Reintentar</button>
  </section>;
}
