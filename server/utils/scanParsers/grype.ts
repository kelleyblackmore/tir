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

// Grype `-o json` output.
// https://github.com/anchore/grype#output-formats

const sourceKinds: Record<string, ScanTargetKind> = {
  image: "image",
  directory: "filesystem",
  file: "filesystem",
  sbom: "sbom",
};

function pickCvss(cvssList: unknown): { score?: number; vector?: string } {
  if (!Array.isArray(cvssList)) return {};
  const entries = cvssList.filter(isObject);
  const v3 =
    entries.find((c) => String(c.version).startsWith("3") && c.type === "Primary") ??
    entries.find((c) => String(c.version).startsWith("3"));
  const chosen = v3 ?? entries[0];
  if (!chosen) return {};
  return {
    score: asNumber(chosen.metrics?.baseScore),
    vector: v3 ? asString(v3.vector) : undefined,
  };
}

function matchFinding(match: Record<string, any>): NormalizedFinding {
  const vuln = isObject(match.vulnerability) ? match.vulnerability : {};
  const artifact = isObject(match.artifact) ? match.artifact : {};
  const related: Record<string, any>[] = (match.relatedVulnerabilities ?? []).filter(isObject);
  const id = asString(vuln.id) ?? "UNKNOWN";

  // GHSA/distro advisories carry their CVE in relatedVulnerabilities
  const cves = uniq(
    [id, ...related.map((r) => r.id)].filter(isCve).map((c: string) => c.toUpperCase()),
  );
  let cvss = pickCvss(vuln.cvss);
  if (cvss.score === undefined) {
    for (const r of related) {
      cvss = pickCvss(r.cvss);
      if (cvss.score !== undefined) break;
    }
  }
  const fixVersions: string[] = vuln.fix?.state === "fixed" ? vuln.fix?.versions ?? [] : [];

  return {
    ruleId: id,
    title: id,
    severity: normalizeSeverity(vuln.severity),
    description:
      asString(vuln.description) ?? related.map((r) => asString(r.description)).find(Boolean),
    cves,
    cwes: uniq((vuln.cwes ?? []).map((c: any) => normalizeCwe(c?.cwe ?? c))),
    references: uniq([asString(vuln.dataSource), ...(vuln.urls ?? [])]),
    cvssScore: cvss.score,
    cvss3Vector: cvss.vector,
    component: {
      name: asString(artifact.name) ?? "unknown",
      version: asString(artifact.version),
      fixedVersion: fixVersions.length ? fixVersions.join(", ") : undefined,
      purl: asString(artifact.purl),
      type: asString(artifact.type),
    },
    location: { path: asString(artifact.locations?.[0]?.path) },
  };
}

export const grypeParser: ScanParser = {
  name: "grype",

  detect(doc) {
    return (
      isObject(doc) &&
      Array.isArray(doc.matches) &&
      (doc.descriptor?.name === "grype" || isObject(doc.source))
    );
  },

  parse(doc) {
    if (!this.detect(doc)) throw new Error("Not a Grype JSON report");
    const report = doc as Record<string, any>;
    const source = isObject(report.source) ? report.source : {};
    const target = source.target;

    const targetName = isObject(target)
      ? asString(target.userInput) ?? asString(target.name) ?? "unknown"
      : asString(target) ?? "unknown";
    const digest = isObject(target)
      ? asString(target.manifestDigest) ?? asString(target.imageID)
      : undefined;

    return {
      tool: { name: "grype", version: asString(report.descriptor?.version) },
      target: {
        kind: sourceKinds[asString(source.type) ?? ""] ?? "other",
        name: targetName,
        digest,
      },
      scanDate: asString(report.descriptor?.timestamp),
      findings: report.matches.filter(isObject).map(matchFinding),
    } satisfies NormalizedScan;
  },
};
