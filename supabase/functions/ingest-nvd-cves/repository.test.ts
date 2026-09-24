import test from "node:test";
import assert from "node:assert/strict";
import { baseCve, v31, v40 } from "./fixtures.ts";
import { parseNvdRecord } from "./normalizer.ts";
import { NvdRepository } from "./repository.ts";

type Row = Record<string, unknown>;

class FakeQuery {
  private operation: "select" | "insert" | "update" = "select";
  private payload: Row = {};
  private filters: Array<[string, unknown]> = [];
  private readonly table: string;
  private readonly database: FakeDb;
  constructor(table: string, database: FakeDb) { this.table = table; this.database = database; }
  select(columns: string) { void columns; return this; }
  eq(column: string, value: unknown) { this.filters.push([column, value]); return this; }
  insert(payload: Row) { this.operation = "insert"; this.payload = payload; return this; }
  update(payload: Row) { this.operation = "update"; this.payload = payload; return this; }
  maybeSingle() { const { data, error } = this.execute(); return Promise.resolve({ data: (data as Row[])[0] ?? null, error }); }
  single() { const { data, error } = this.execute(); return Promise.resolve({ data: (data as Row[])[0] ?? null, error }); }
  then(resolve: (value: { data: Row[]; error: null }) => void) { resolve(this.execute()); }
  private execute() {
    const rows = this.database.tables[this.table] ?? [];
    const matches = (row: Row) => this.filters.every(([key, value]) => row[key] === value);
    if (this.operation === "insert") {
      const row = { id: `id-${this.database.nextId++}`, ...this.payload };
      rows.push(row); this.database.tables[this.table] = rows;
      return { data: [row], error: null };
    }
    if (this.operation === "update") {
      const found = rows.filter(matches);
      found.forEach((row) => Object.assign(row, this.payload));
      return { data: found, error: null };
    }
    return { data: rows.filter(matches), error: null };
  }
}

class FakeDb {
  nextId = 1;
  tables: Record<string, Row[]> = {
    cves: [], cve_sources: [], cve_cvss_metrics: [], cve_references: [],
  };
  from(table: string) { return new FakeQuery(table, this); }
  async rpc(name: string, input: Row) {
    assert.equal(name, "observe_nvd_cve_source");
    let row = this.tables.cve_sources.find((candidate) => candidate.cve_id === input.p_cve_id && candidate.source_id === input.p_source_id);
    if (!row) { row = { cve_id: input.p_cve_id, source_id: input.p_source_id }; this.tables.cve_sources.push(row); }
    Object.assign(row, {
      source_record_id: input.p_source_record_id, source_url: input.p_source_url,
      source_published_at: input.p_source_published_at, source_updated_at: input.p_source_updated_at,
      source_status: input.p_source_status,
    });
    return { data: null, error: null };
  }
}

test("first NVD observation inserts, identical replay skips, changed metric updates", async () => {
  const db = new FakeDb();
  const repository = new NvdRepository(db as never);
  const record = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [v31] } });
  assert.equal(await repository.processRecord("nvd", record), "inserted");
  assert.equal(await repository.processRecord("nvd", record), "skipped");
  assert.equal(db.tables.cves[0].is_public, undefined); // DB default, never set by collector.
  assert.equal(db.tables.cve_cvss_metrics.length, 1);
  assert.equal(db.tables.cve_cvss_metrics[0].is_primary, true);
  const changed = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [
    { ...v31, cvssData: { ...v31.cvssData, baseScore: 9.1 } },
  ] } });
  assert.equal(await repository.processRecord("nvd", changed), "updated");
  assert.equal(db.tables.cve_cvss_metrics.length, 1);
  assert.equal(db.tables.cve_cvss_metrics[0].base_score, 9.1);
});

test("existing CISA CVE and reference retain their provenance", async () => {
  const db = new FakeDb();
  const record = parseNvdRecord(baseCve);
  db.tables.cves.push({
    id: "cisa-cve", cve_id: record.cveId, status: "published",
    description: "CISA description", description_source_id: "cisa",
    published_at: record.publishedAt, last_modified_at: record.modifiedAt,
    is_public: false,
  });
  db.tables.cve_references.push({
    id: "cisa-ref", cve_id: "cisa-cve", source_id: "cisa",
    normalized_url: record.references[0].normalizedUrl, url: record.references[0].url,
  });
  const repository = new NvdRepository(db as never);
  assert.equal(await repository.processRecord("nvd", record), "updated"); // New NVD source observation.
  assert.equal(await repository.processRecord("nvd", record), "skipped");
  assert.equal(db.tables.cves[0].description, "CISA description");
  assert.equal(db.tables.cves[0].is_public, false);
  assert.equal(db.tables.cve_references.length, 1);
  assert.equal(db.tables.cve_references[0].source_id, "cisa");
});

test("same contributor and CVSS version can have distinct metric types", async () => {
  const db = new FakeDb();
  const repository = new NvdRepository(db as never);
  const record = parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [
    v31, { ...v31, type: "Secondary", cvssData: { ...v31.cvssData, baseScore: 8.1 } },
  ] } });
  assert.equal(await repository.processRecord("nvd", record), "inserted");
  assert.equal(db.tables.cve_cvss_metrics.length, 2);
  assert.equal(db.tables.cve_cvss_metrics.filter((row) => row.is_primary).length, 1);
  assert.equal(db.tables.cve_cvss_metrics.find((row) => row.is_primary)?.base_score, 9.8);
  assert.equal(await repository.processRecord("nvd", record), "skipped");
});

test("better CVSS replaces the primary but keeps older metric", async () => {
  const db = new FakeDb();
  const repository = new NvdRepository(db as never);
  await repository.processRecord("nvd", parseNvdRecord({ ...baseCve, metrics: { cvssMetricV31: [v31] } }));
  const record = parseNvdRecord({ ...baseCve, metrics: {
    cvssMetricV31: [v31], cvssMetricV40: [{ ...v40, type: "Primary" }],
  } });
  assert.equal(await repository.processRecord("nvd", record), "updated");
  assert.equal(db.tables.cve_cvss_metrics.length, 2);
  assert.equal(db.tables.cve_cvss_metrics.filter((row) => row.is_primary).length, 1);
  assert.equal(db.tables.cve_cvss_metrics.find((row) => row.is_primary)?.version, "4.0");
  assert.equal(await repository.processRecord("nvd", record), "skipped");
});
