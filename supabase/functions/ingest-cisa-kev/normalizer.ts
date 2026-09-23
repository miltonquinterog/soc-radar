import { RecordValidationError, type CisaKevRecord, type NormalizedKevRecord } from "./types.ts";

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export function normalizeKevRecord(raw: CisaKevRecord): NormalizedKevRecord {
  const cveId = requiredString(raw.cveID, "cve_id").toUpperCase();
  if (!CVE_PATTERN.test(cveId)) throw new RecordValidationError("cve_id_invalid");

  const vendorName = requiredString(raw.vendorProject, "vendor_project");
  const productName = requiredString(raw.product, "product");
  const requiredAction = requiredString(raw.requiredAction, "required_action");
  const dateAdded = normalizeDate(requiredString(raw.dateAdded, "date_added"), "date_added");
  const dueDate = optionalDate(raw.dueDate, "due_date");
  if (dueDate && dueDate < dateAdded) throw new RecordValidationError("due_date_before_date_added");

  return {
    cveId,
    vendorName,
    vendorSlug: normalizeSlug(vendorName),
    productName,
    productSlug: normalizeSlug(productName),
    vulnerabilityName: optionalString(raw.vulnerabilityName),
    dateAdded,
    dueDate,
    shortDescription: optionalString(raw.shortDescription),
    requiredAction,
    knownRansomwareCampaignUse: normalizeRansomware(raw.knownRansomwareCampaignUse),
    notes: optionalString(raw.notes),
  };
}

export function normalizeSlug(value: string) {
  const slug = value.trim().normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase()
    .replace(/&/g, " and ").replace(/[^a-z0-9]+/g, "-").replace(/-+/g, "-").replace(/^-+|-+$/g, "");
  if (!slug) throw new RecordValidationError("slug_empty");
  return slug;
}

export function normalizeRansomware(value: unknown) {
  if (typeof value !== "string") return null;
  return value.trim().toLowerCase() === "known" ? true : null;
}

function requiredString(value: unknown, field: string) {
  const normalized = optionalString(value);
  if (!normalized) throw new RecordValidationError(`${field}_missing`);
  return normalized;
}

function optionalString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function optionalDate(value: unknown, field: string) {
  const normalized = optionalString(value);
  return normalized ? normalizeDate(normalized, field) : null;
}

function normalizeDate(value: string, field: string) {
  if (!DATE_PATTERN.test(value) || new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) !== value) {
    throw new RecordValidationError(`${field}_invalid`);
  }
  return value;
}
