export const baseCve = {
  id: "CVE-2026-12345",
  vulnStatus: "Analyzed",
  published: "2026-09-20T10:00:00.000",
  lastModified: "2026-09-21T10:00:00.000",
  descriptions: [{ lang: "en", value: "Example NVD description" }],
  metrics: {},
  references: [{ url: "https://example.org/advisory#section", tags: ["Vendor Advisory"] }],
};

export function pageFor(cve: unknown = baseCve) {
  return {
    resultsPerPage: 25, startIndex: 0, totalResults: 1,
    vulnerabilities: [{ cve }],
  };
}

export const v31 = {
  source: "nvd@nist.gov", type: "Primary",
  cvssData: { version: "3.1", baseScore: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
};
export const v40 = {
  source: "vendor@example.org", type: "Secondary",
  cvssData: { version: "4.0", baseScore: 8.7, vectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" },
};
