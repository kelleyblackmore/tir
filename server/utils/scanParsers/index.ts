import { trivyParser } from "./trivy";
import { grypeParser } from "./grype";
import type { NormalizedScan, ScanParser } from "~/types/scan";

// Register new scanner formats here. Order matters only if two detectors could match
// the same document, so keep detectors specific.
export const scanParsers: ScanParser[] = [trivyParser, grypeParser];

export function findScanParser(doc: unknown): ScanParser | undefined {
  return scanParsers.find((parser) => parser.detect(doc));
}

// Parses raw file contents into a NormalizedScan, or returns undefined when no
// registered parser recognizes the file.
export function parseScanFile(content: string): NormalizedScan | undefined {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return undefined;
  }
  return findScanParser(doc)?.parse(doc);
}
