type TrendBar = { label: string; low: number; medium: number; high: number; critical: number };

// Muestra ficticia coherente con las métricas de CVE del dashboard.
const trend: TrendBar[] = [
  { label: "Lun", low: 2, medium: 6, high: 3, critical: 1 },
  { label: "Mar", low: 2, medium: 7, high: 6, critical: 2 },
  { label: "Mié", low: 2, medium: 6, high: 5, critical: 1 },
  { label: "Jue", low: 3, medium: 8, high: 7, critical: 2 },
  { label: "Vie", low: 2, medium: 6, high: 4, critical: 1 },
  { label: "Sáb", low: 2, medium: 10, high: 6, critical: 2 },
  { label: "Dom", low: 3, medium: 11, high: 7, critical: 3 },
];

const severity = [
  { key: "critical", label: "Críticos", value: 12, color: "var(--red)" },
  { key: "high", label: "Altos", value: 38, color: "var(--high)" },
  { key: "medium", label: "Medios", value: 54, color: "var(--yellow)" },
  { key: "low", label: "Bajos", value: 16, color: "#94a3b8" },
] as const;

const total = severity.reduce((sum, item) => sum + item.value, 0);

export function TrendChart() {
  const max = 26;
  return (
    <div className="chart-wrap">
      <div className="chart-summary"><strong>{total}</strong><span>CVE añadidos en los últimos 7 días</span></div>
      <div className="chart-legend">
        {severity.map((item) => <span key={item.key}><i style={{ background: item.color }} />{item.label}</span>)}
      </div>
      <div className="bar-chart" role="img" aria-label="CVE añadidos por día y severidad durante los últimos siete días">
        {trend.map((day) => (
          <div className="bar-group" key={day.label}>
            <div className="bar-stack">
              {severity.slice().reverse().map((item) => (
                <span
                  className={`bar ${item.key}`}
                  key={item.key}
                  style={{ height: `${(day[item.key] / max) * 100}%` }}
                  title={`${day.label}: ${day[item.key]} CVE ${item.label.toLowerCase()}`}
                />
              ))}
            </div>
            <span>{day.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function SeverityDonut() {
  const circumference = 2 * Math.PI * 52;
  return (
    <div className="donut-layout">
      <div className="donut" role="img" aria-label="Distribución de 120 CVE añadidos: 12 críticos, 38 altos, 54 medios y 16 bajos">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          {severity.map((item, index) => {
            const length = (item.value / total) * circumference;
            const previousValues = severity.slice(0, index).reduce((sum, previous) => sum + previous.value, 0);
            const offset = (previousValues / total) * circumference;
            return (
              <circle key={item.key} cx="60" cy="60" r="52" fill="none" stroke={item.color} strokeWidth="14"
                strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={-offset}
                transform="rotate(-90 60 60)" />
            );
          })}
        </svg>
        <div><strong>{total}</strong><span>CVE</span></div>
      </div>
      <div className="donut-list">
        {severity.map((item) => <div key={item.key}><span><i style={{ background: item.color }} />{item.label}</span><b>{item.value}</b></div>)}
      </div>
    </div>
  );
}
