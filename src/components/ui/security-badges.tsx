import type {Severity} from "@/types/security";
export function SeverityBadge({severity}:{severity:Severity}){const label={critical:"Crítica",high:"Alta",medium:"Media",low:"Baja"}[severity];return <span className={`badge ${severity}`}>{label}</span>}
export function KevBadge(){return <span className="badge kev">CISA KEV</span>}
export function CvssScore({score,severity}:{score:number;severity:Severity}){return <span className={`score ${severity}`}>{score.toFixed(1)}</span>}
export function StatCard({label,value,detail}:{label:string;value:string;detail:string}){return <article className="stat"><div className="meta">{label}</div><div className="stat-value">{value}</div><div className="trend">{detail}</div></article>}