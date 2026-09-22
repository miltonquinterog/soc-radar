export type Severity="critical"|"high"|"medium"|"low";
export type Cve={id:string;title:string;severity:Severity;score:number;vendor:string;product:string;published:string;kev:boolean};
export type Advisory={id:string;title:string;vendor:string;severity:Severity;published:string;cves:string[]};
export type NewsItem={id:string;title:string;source:string;published:string;category:string};