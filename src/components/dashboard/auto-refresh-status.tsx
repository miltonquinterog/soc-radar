"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import styles from "./auto-refresh-status.module.css";

const REFRESH_INTERVAL_MS = 5 * 60 * 1000;

export function AutoRefreshStatus() {
  const router = useRouter();
  const nextRefreshAt = useRef(0);
  const [secondsRemaining, setSecondsRemaining] = useState(300);
  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  useEffect(() => {
    nextRefreshAt.current = Date.now() + REFRESH_INTERVAL_MS;
    const timer = window.setInterval(() => {
      const remaining = Math.ceil((nextRefreshAt.current - Date.now()) / 1000);
      if (remaining <= 0) {
        nextRefreshAt.current = Date.now() + REFRESH_INTERVAL_MS;
        setSecondsRemaining(300);
        setLastRefresh(new Date().toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" }));
        router.refresh();
      } else {
        setSecondsRemaining(remaining);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [router]);

  const refreshNow = () => {
    nextRefreshAt.current = Date.now() + REFRESH_INTERVAL_MS;
    setSecondsRemaining(300);
    setLastRefresh(new Date().toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" }));
    router.refresh();
  };

  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = String(secondsRemaining % 60).padStart(2, "0");

  return (
    <div className={styles.status} aria-label="Estado de actualización del dashboard">
      <span className={styles.indicator} aria-hidden="true" />
      <span>Vista de demostración</span>
      <span className={styles.countdown} aria-live="off">Próxima recarga en {minutes}:{seconds}</span>
      {lastRefresh && <span className={styles.last}>Vista actualizada a las {lastRefresh}</span>}
      <button type="button" onClick={refreshNow}>Actualizar ahora</button>
    </div>
  );
}
