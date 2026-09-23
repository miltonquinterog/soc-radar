import { parseCisaKevCatalog } from "./cisa.ts";
import { normalizeKevRecord, normalizeRansomware, normalizeSlug } from "./normalizer.ts";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const valid = {
  cveID: " cve-2026-12345 ", vendorProject: "Mícrösoft & Co.", product: "Windows Server", vulnerabilityName: "Example",
  dateAdded: "2026-09-22", shortDescription: "Example description", requiredAction: "Apply updates.", dueDate: "2026-09-25",
  knownRansomwareCampaignUse: "Known", notes: "Example note",
};

Deno.test("normalizes CVE, conservative vendor slug, product and ransomware", () => {
  const record = normalizeKevRecord(valid);
  assert(record.cveId === "CVE-2026-12345", "CVE should normalize to uppercase");
  assert(record.vendorSlug === "microsoft-and-co", "vendor slug should preserve legal words");
  assert(record.productSlug === "windows-server", "product slug should normalize");
  assert(record.knownRansomwareCampaignUse === true, "Known should map to true");
});

Deno.test("maps Unknown ransomware to null", () => assert(normalizeRansomware("Unknown") === null, "Unknown must remain null"));
Deno.test("rejects malformed CVEs and invalid dates", () => {
  let invalidCve = false;
  try { normalizeKevRecord({ ...valid, cveID: "invalid" }); } catch { invalidCve = true; }
  let invalidDate = false;
  try { normalizeKevRecord({ ...valid, dueDate: "2026-02-30" }); } catch { invalidDate = true; }
  assert(invalidCve && invalidDate, "invalid records must fail");
});

Deno.test("rejects invalid feed envelopes", () => {
  let failed = false;
  try { parseCisaKevCatalog(JSON.stringify({ catalogVersion: "1", dateReleased: "2026-09-22T00:00:00Z", count: 1, vulnerabilities: [] })); } catch { failed = true; }
  assert(failed, "empty feeds must fail");
});

Deno.test("normalizes punctuation without fuzzy matching", () => {
  assert(normalizeSlug("Microsoft Corporation") === "microsoft-corporation", "legal suffixes must remain");
});
