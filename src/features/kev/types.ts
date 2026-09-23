export type KevOverview = {
  total_kev: number;
  added_last_7_days: number;
  known_ransomware_count: number;
  unknown_ransomware_count: number;
  latest_date_added: string | null;
  total_vendors: number;
  total_products: number;
};

export type KevEntry = {
  cve_id: string;
  source_vendor_name: string | null;
  source_product_name: string | null;
  source_vulnerability_name: string | null;
  date_added: string;
  due_date: string | null;
  required_action: string;
  known_ransomware_campaign_use: boolean | null;
};

export type KevVendor = { vendor_name: string; kev_count: number };
export type KevProduct = { vendor_name: string; product_name: string; kev_count: number };

export type KevDashboardData = {
  overview: KevOverview;
  entries: KevEntry[];
  vendors: KevVendor[];
  products: KevProduct[];
  loadedAt: string;
};
