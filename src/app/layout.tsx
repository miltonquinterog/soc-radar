import type { Metadata } from "next"; import "./globals.css";
export const metadata: Metadata = { title: "SOC Radar", description: "Inteligencia de ciberseguridad para equipos SOC." };
export default function RootLayout({children}:{children:React.ReactNode}) { return <html lang="es"><body>{children}</body></html>; }