import type { ScanSeverity } from "~/types/scan";

const severityMap: Record<string, ScanSeverity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  moderate: "Medium",
  low: "Low",
  negligible: "Low",
  info: "None",
  informational: "None",
  none: "None",
  unknown: "None",
};

export function normalizeSeverity(value: unknown): ScanSeverity {
  if (typeof value !== "string") return "None";
  return severityMap[value.trim().toLowerCase()] ?? "None";
}

export function severityFromCvss(score: number | undefined): ScanSeverity | undefined {
  if (score === undefined || Number.isNaN(score)) return undefined;
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score > 0) return "Low";
  return "None";
}

const cvePattern = /^CVE-\d{4}-\d{4,}$/i;

export function isCve(id: unknown): id is string {
  return typeof id === "string" && cvePattern.test(id);
}

export function normalizeCwe(id: unknown): string | undefined {
  if (typeof id === "number") return `CWE-${id}`;
  if (typeof id !== "string") return undefined;
  const match = id.match(/(\d+)/);
  return match ? `CWE-${match[1]}` : undefined;
}

export function uniq<T>(values: (T | undefined | null)[]): T[] {
  return [...new Set(values.filter((v): v is T => v !== undefined && v !== null && v !== ""))];
}

export function isObject(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

export function asNumber(value: unknown): number | undefined {
  const n = typeof value === "string" ? Number(value) : value;
  return typeof n === "number" && Number.isFinite(n) ? n : undefined;
}
