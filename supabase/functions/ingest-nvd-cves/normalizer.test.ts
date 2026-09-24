import test from "node:test";
import assert from "node:assert/strict";
import { baseCve, pageFor, v31, v40 } from "./fixtures.ts";
import { parseNvdPage, parseNvdRecord } from "./normalizer.ts";
import { canonicalPatch, choosePrimaryMetric } from "./policy.ts";

test("new CVE: parses identity, English description, status and references", () => {
  const record = parseNvdPage(pageFor()).records[0];
  assert.equal(record.cveId, "CVE-2026-12345");
  assert.equal(record.status, "published");
  assert.equal(record.description, "Example NVD description");
  assert.equal(record.references[0].normalizedUrl, "https://example.org/advisory");
});

test("existing CISA description is preserved and publication date is only filled when null", () => {
  const incoming = parseNvdRecord(baseCve);
  const patch = canonicalPatch({
    status: "published", description: "CISA description", description_source_id: "cisa",
    published_at: "2026-09-19T00:00:00Z", last_modified_at: "2026-09-22T00:00:00Z",
  }, incoming, "nvd");
  assert.equal(patch.description, undefined);
  assert.equal(patch.published_at, undefined);
  assert.equal(patch.last_modified_at, undefined);
});

test("identical NVD canonical record is skipped by patch policy", () => {
  const incoming = parseNvdRecord(baseCve);
  const patch = canonicalPatch({
    status: incoming.status, description: incoming.description, description_source_id: "nvd",
    published_at: incoming.publishedAt, last_modified_at: incoming.modifiedAt,
  }, incoming, "nvd");
  assert.deepEqual(patch, {});
});

test("NVD-owned description can change; another source cannot be overwritten", () => {
  const incoming = parseNvdRecord({ ...baseCve, descriptions: [{ lang: "en", value: "Updated" }] });
  const common = { status: "published", description: "Old", published_at: incoming.publishedAt, last_modified_at: incoming.modifiedAt };
  assert.equal(canonicalPatch({ ...common, description_source_id: "nvd" }, incoming, "nvd").description, "Updated");
  assert.equal(canonicalPatch({ ...common, description_source_id: "cisa" }, incoming, "nvd").description, undefined);
});

test("rejected and reserved status mapping is explicit", () => {
  assert.equal(parseNvdRecord({ ...baseCve, vulnStatus: "Rejected" }).status, "rejected");
  assert.equal(parseNvdRecord({ ...baseCve, vulnStatus: "Reserved" }).status, "reserved");
  assert.equal(parseNvdRecord({ ...baseCve, vulnStatus: "Future State" }).status, "unknown");
});

test("CVE without CVSS is accepted", () => {
  assert.deepEqual(parseNvdRecord(baseCve).metrics, []);
});

test("CVSS v3.1 and v4.0 preserve contributor, type, vector and score", () => {
  const record = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [v31], cvssMetricV40: [v40] } });
  assert.equal(record.metrics.length, 2);
  assert.equal(record.metrics[0].version, "3.1");
  assert.equal(record.metrics[0].contributor, "nvd@nist.gov");
  assert.equal(record.metrics[1].version, "4.0");
  assert.equal(record.metrics[1].metricType, "secondary");
  assert.equal(choosePrimaryMetric(record.metrics)?.version, "3.1");
});

test("multiple contributors of one CVSS version are preserved; tie-break is deterministic", () => {
  const record = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [
    { ...v31, source: "vendor@example.org" }, v31,
  ] } });
  assert.equal(record.metrics.length, 2);
  assert.equal(choosePrimaryMetric(record.metrics)?.contributor, "nvd@nist.gov");
});

test("higher version wins when metric type is equal", () => {
  const record = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [v31], cvssMetricV40: [{ ...v40, type: "Primary" }] } });
  assert.equal(choosePrimaryMetric(record.metrics)?.version, "4.0");
});

test("duplicate references are collapsed by normalized URL", () => {
  const record = parseNvdRecord({ ...baseCve, references: [
    { url: "https://example.org/advisory#one", tags: ["Vendor Advisory"] },
    { url: "https://example.org/advisory#two", tags: ["Patch"] },
  ] });
  assert.equal(record.references.length, 1);
});

test("conflicting duplicate CVSS contribution fails instead of silently overwriting", () => {
  assert.throws(() => parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [v31, { ...v31, cvssData: { ...v31.cvssData, baseScore: 7.1 } }] } }));
});
