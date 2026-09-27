import {
  asNumber,
  asString,
  isCve,
  isObject,
  normalizeCwe,
  normalizeSeverity,
  uniq,
} from "./common";
import type { NormalizedFinding, NormalizedScan, ScanParser, ScanTargetKind } from "~/types/scan";

// Trivy `--format json` output (SchemaVersion 2).
// https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#json

const artifactKinds: Record<string, ScanTargetKind> = {
  container_image: "image",
  filesystem: "filesystem",
  repository: "repository",
  cyclonedx: "sbom",
  spdx: "sbom",
  vm: "host",
};

function pickCvss(cvss: unknown): { score?: number; vector?: string } {
  if (!isObject(cvss)) return {};
  // Prefer NVD, then whichever vendor source carries a v3 vector
  const sources = [cvss.nvd, ...Object.values(cvss)].filter(isObject);
  for (const source of sources) {
    const vector = asString(source.V3Vector);
    const score = asNumber(source.V3Score);
    if (vector || score !== undefined) return { score, vector };
  }
  for (const source of sources) {
    const score = asNumber(source.V2Score);
    if (score !== undefined) return { score };
  }
  return {};
}

function vulnerabilityFinding(vuln: Record<string, any>, target: string): NormalizedFinding {
  const id = asString(vuln.VulnerabilityID) ?? "UNKNOWN";
  const { score, vector } = pickCvss(vuln.CVSS);
  return {
    ruleId: id,
    title: asString(vuln.Title) ?? id,
    severity: normalizeSeverity(vuln.Severity),
    description: asString(vuln.Description),
    cves: isCve(id) ? [id.toUpperCase()] : [],
    cwes: uniq((vuln.CweIDs ?? []).map(normalizeCwe)),
    references: uniq([asString(vuln.PrimaryURL), ...(vuln.References ?? [])]),
    cvssScore: score,
    cvss3Vector: vector,
    component: {
      name: asString(vuln.PkgName) ?? "unknown",
      version: asString(vuln.InstalledVersion),
      fixedVersion: asString(vuln.FixedVersion),
      purl: asString(vuln.PkgIdentifier?.PURL),
    },
    location: { path: asString(vuln.PkgPath) ?? target },
  };
}

function misconfigurationFinding(misconf: Record<string, any>, target: string): NormalizedFinding {
  const id = asString(misconf.AVDID) ?? asString(misconf.ID) ?? "UNKNOWN";
  return {
    ruleId: id,
    title: asString(misconf.Title) ?? id,
    severity: normalizeSeverity(misconf.Severity),
    description: asString(misconf.Description),
    solution: asString(misconf.Resolution),
    cves: [],
    cwes: [],
    references: uniq([asString(misconf.PrimaryURL), ...(misconf.References ?? [])]),
    location: { path: target, line: asNumber(misconf.CauseMetadata?.StartLine) },
    evidence: asString(misconf.Message),
  };
}

function secretFinding(secret: Record<string, any>, target: string): NormalizedFinding {
  const id = asString(secret.RuleID) ?? "secret";
  return {
    ruleId: `secret:${id}`,
    title: asString(secret.Title) ?? id,
    severity: normalizeSeverity(secret.Severity),
    description: asString(secret.Category),
    solution: "Remove the secret from the artifact and rotate the credential.",
    cves: [],
    cwes: ["CWE-798"],
    references: [],
    location: { path: target, line: asNumber(secret.StartLine) },
    // Trivy masks the secret value in Match
    evidence: asString(secret.Match),
  };
}

export const trivyParser: ScanParser = {
  name: "trivy",

  detect(doc) {
    return isObject(doc) && typeof doc.SchemaVersion === "number" && Array.isArray(doc.Results);
  },

  parse(doc) {
    if (!this.detect(doc)) throw new Error("Not a Trivy JSON report");
    const report = doc as Record<string, any>;
    const findings: NormalizedFinding[] = [];

    for (const result of report.Results) {
      if (!isObject(result)) continue;
      const target = asString(result.Target) ?? "";
      for (const vuln of result.Vulnerabilities ?? []) {
        if (isObject(vuln)) findings.push(vulnerabilityFinding(vuln, target));
      }
      for (const misconf of result.Misconfigurations ?? []) {
        if (isObject(misconf) && misconf.Status !== "PASS") {
          findings.push(misconfigurationFinding(misconf, target));
        }
      }
      for (const secret of result.Secrets ?? []) {
        if (isObject(secret)) findings.push(secretFinding(secret, target));
      }
    }

    const metadata = isObject(report.Metadata) ? report.Metadata : {};
    return {
      tool: { name: "trivy" },
      target: {
        kind: artifactKinds[asString(report.ArtifactType) ?? ""] ?? "other",
        name: asString(report.ArtifactName) ?? "unknown",
        digest: asString(metadata.RepoDigests?.[0]) ?? asString(metadata.ImageID),
      },
      scanDate: asString(report.CreatedAt),
      findings,
    } satisfies NormalizedScan;
  },
};
