export function formatKevDate(value: string | null): string {
  if (!value) return "No indicada";
  const [year, month, day] = value.split("-");
  return year && month && day ? `${day}/${month}/${year}` : value;
}

export function formatRansomwareUse(value: boolean | null): string {
  if (value === true) return "Sí";
  if (value === false) return "No";
  return "No indicado";
}
