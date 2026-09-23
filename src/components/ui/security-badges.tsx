import type {Severity} from "@/types/security";
export function SeverityBadge({severity}:{severity:Severity}){const label={critical:"Crítica",high:"Alta",medium:"Media",low:"Baja"}[severity];return <span className={`badge ${severity}`}>{label}</span>}
export function KevBadge(){return <span className="badge kev">CISA KEV</span>}
export function CvssScore({score,severity}:{score:number;severity:Severity}){return <span className={`score ${severity}`}>{score.toFixed(1)}</span>}
export function StatCard({label,value,detail,tone="medium",source}:{label:string;value:string;detail:string;tone?:"critical"|"high"|"medium"|"kev";source:"demo"|"cisa"}){return <article className={`stat stat-${tone}`}><div className="stat-top"><span className="meta">{label}</span><span className={`data-source data-source-${source}`}>{source==="cisa"?"CISA KEV":"DEMO"}</span></div><div className="stat-value">{value}</div><div className="trend">{detail}</div></article>}
