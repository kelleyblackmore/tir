// Tool-agnostic scan result shape. Every scanner parser (Trivy, Grype, SARIF, ...)
// converts its native output into a NormalizedScan so a single importer can store it.

export const ScanSeverities = ["Critical", "High", "Medium", "Low", "None"] as const;
export type ScanSeverity = (typeof ScanSeverities)[number];

export const ScanTargetKinds = [
  "host",
  "image",
  "filesystem",
  "repository",
  "sbom",
  "other",
] as const;
export type ScanTargetKind = (typeof ScanTargetKinds)[number];

export type ScanComponent = {
  name: string;
  version?: string;
  fixedVersion?: string;
  purl?: string;
  type?: string;
};

export type ScanLocation = {
  path?: string;
  line?: number;
  url?: string;
  port?: number;
};

export type NormalizedFinding = {
  // Tool-specific identifier of the finding definition (CVE id, GHSA id, rule id, ...)
  ruleId: string;
  title: string;
  severity: ScanSeverity;
  description?: string;
  solution?: string;
  cves: string[];
  cwes: string[];
  references: string[];
  cvssScore?: number;
  cvss3Vector?: string;
  component?: ScanComponent;
  location?: ScanLocation;
  evidence?: string;
};

export type NormalizedScan = {
  tool: { name: string; version?: string };
  target: { kind: ScanTargetKind; name: string; digest?: string };
  scanDate?: string;
  findings: NormalizedFinding[];
};

export interface ScanParser {
  // Stable identifier, also used as the ScanTool name
  name: string;
  // Returns true when the parsed document is this parser's format
  detect(doc: unknown): boolean;
  parse(doc: unknown): NormalizedScan;
}
