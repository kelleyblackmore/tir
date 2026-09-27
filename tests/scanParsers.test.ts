import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseScanFile, findScanParser } from "~/server/utils/scanParsers";
import { normalizeSeverity, severityFromCvss } from "~/server/utils/scanParsers/common";

const fixture = (name: string) =>
  readFileSync(new URL(`./fixtures/scans/${name}`, import.meta.url), "utf-8");

describe("parser detection", () => {
  it("picks the right parser per format", () => {
    expect(findScanParser(JSON.parse(fixture("trivy-image.json")))?.name).toBe("trivy");
    expect(findScanParser(JSON.parse(fixture("grype-image.json")))?.name).toBe("grype");
  });

  it("returns undefined for unknown JSON and non-JSON", () => {
    expect(parseScanFile('{"foo": 1}')).toBeUndefined();
    expect(parseScanFile("<xml/>")).toBeUndefined();
    // .cklb files are JSON too and must not be claimed by a scan parser
    expect(parseScanFile('{"title":"x","stigs":[],"target_data":{}}')).toBeUndefined();
  });
});

describe("trivy parser", () => {
  const scan = parseScanFile(fixture("trivy-image.json"))!;

  it("reads the target", () => {
    expect(scan.tool.name).toBe("trivy");
    expect(scan.target).toEqual({
      kind: "image",
      name: "registry.example.mil/app/web:1.4.2",
      digest:
        "registry.example.mil/app/web@sha256:2222222222222222222222222222222222222222222222222222222222222222",
    });
    expect(scan.scanDate).toBe("2026-09-01T12:00:00.000000000Z");
  });

  it("maps OS package vulnerabilities", () => {
    const finding = scan.findings.find((f) => f.ruleId === "CVE-2023-5678")!;
    expect(finding.severity).toBe("Medium");
    expect(finding.cves).toEqual(["CVE-2023-5678"]);
    expect(finding.cwes).toEqual(["CWE-606", "CWE-754"]);
    expect(finding.cvssScore).toBe(5.3);
    expect(finding.cvss3Vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
    expect(finding.component).toMatchObject({
      name: "libcrypto3",
      version: "3.1.3-r0",
      fixedVersion: "3.1.4-r1",
    });
    expect(finding.references[0]).toBe("https://avd.aquasec.com/nvd/cve-2023-5678");
  });

  it("handles non-CVE ids and unknown severity", () => {
    const ghsa = scan.findings.find((f) => f.ruleId === "GHSA-grv7-fg5c-xmjg")!;
    expect(ghsa.cves).toEqual([]);
    expect(ghsa.location?.path).toBe("app/node_modules/braces/package.json");
    const unknown = scan.findings.find((f) => f.ruleId === "CVE-2024-99999")!;
    expect(unknown.severity).toBe("None");
    expect(unknown.title).toBe("CVE-2024-99999");
  });

  it("keeps failed misconfigurations and secrets, drops passes", () => {
    expect(scan.findings.map((f) => f.ruleId)).toEqual([
      "CVE-2023-5678",
      "GHSA-grv7-fg5c-xmjg",
      "CVE-2024-99999",
      "AVD-DS-0002",
      "secret:aws-access-key-id",
    ]);
    const misconf = scan.findings.find((f) => f.ruleId === "AVD-DS-0002")!;
    expect(misconf.solution).toContain("USER");
    expect(misconf.location).toEqual({ path: "Dockerfile", line: 1 });
    const secret = scan.findings.find((f) => f.ruleId === "secret:aws-access-key-id")!;
    expect(secret.severity).toBe("Critical");
    expect(secret.cwes).toEqual(["CWE-798"]);
  });
});

describe("grype parser", () => {
  const scan = parseScanFile(fixture("grype-image.json"))!;

  it("reads the target and tool version", () => {
    expect(scan.tool).toEqual({ name: "grype", version: "0.80.0" });
    expect(scan.target.kind).toBe("image");
    expect(scan.target.name).toBe("registry.example.mil/app/web:1.4.2");
    expect(scan.target.digest).toBe(
      "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    );
    expect(scan.findings).toHaveLength(3);
  });

  it("falls back to related vulnerabilities for CVSS and description", () => {
    const finding = scan.findings.find((f) => f.ruleId === "CVE-2023-5678")!;
    expect(finding.cvssScore).toBe(5.3);
    expect(finding.cvss3Vector).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
    expect(finding.description).toContain("X9.42");
    expect(finding.component?.fixedVersion).toBe("3.1.4-r1");
  });

  it("collects CVEs from GHSA related vulnerabilities", () => {
    const finding = scan.findings.find((f) => f.ruleId === "GHSA-grv7-fg5c-xmjg")!;
    expect(finding.cves).toEqual(["CVE-2024-4068"]);
    expect(finding.severity).toBe("High");
    expect(finding.component?.purl).toBe("pkg:npm/braces@3.0.2");
  });

  it("only reports fix versions when a fix exists", () => {
    const finding = scan.findings.find((f) => f.ruleId === "CVE-2005-2541")!;
    expect(finding.component?.fixedVersion).toBeUndefined();
    expect(finding.severity).toBe("Low");
  });
});

describe("severity helpers", () => {
  it("normalizes tool severities", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("Critical");
    expect(normalizeSeverity("moderate")).toBe("Medium");
    expect(normalizeSeverity(undefined)).toBe("None");
  });

  it("maps CVSS scores to severities", () => {
    expect(severityFromCvss(9.8)).toBe("Critical");
    expect(severityFromCvss(7.0)).toBe("High");
    expect(severityFromCvss(5.3)).toBe("Medium");
    expect(severityFromCvss(0.1)).toBe("Low");
    expect(severityFromCvss(undefined)).toBeUndefined();
  });
});
