/* eslint-disable camelcase */
import { createHash } from "node:crypto";
import { Op, type Transaction } from "sequelize";
import type { NormalizedFinding, NormalizedScan } from "~/types/scan";
import {
  System,
  EvaluationItem,
  ScanTool,
  ScanFinding,
  ScanReport,
  ScanReportItem,
  ScanFinding_Boundary,
} from "~/db/models";
import { Cve } from "~/db/models/cve";

export type ScanImportResult = {
  tool: string;
  target: string;
  skipped: boolean;
  findings: number;
};

// Hash of the normalized content, ignoring the scan timestamp, so re-importing an
// unchanged scan is a no-op.
function scanHash(scan: NormalizedScan): string {
  return createHash("sha256")
    .update(JSON.stringify({ tool: scan.tool.name, target: scan.target, findings: scan.findings }))
    .digest("hex");
}

// Overrides follow a finding in the same component/location across re-imports, the
// way NessusOverride locks follow a plugin on a system.
function overrideKey(findingId: number, componentName?: string | null, path?: string | null) {
  return `${findingId}|${componentName ?? ""}|${path ?? ""}`;
}

async function upsertFinding(
  finding: NormalizedFinding,
  toolId: number,
  existing: Map<string, ScanFinding>,
  transaction: Transaction,
): Promise<ScanFinding> {
  const values = {
    title: finding.title,
    severity: finding.severity,
    description: finding.description ?? null,
    solution: finding.solution ?? null,
    cwes: finding.cwes.length ? finding.cwes.join(",") : null,
    referenceUrls: finding.references.length ? finding.references.join("\n") : null,
  };

  const current = existing.get(finding.ruleId);
  if (current) {
    current.set(values);
    if (current.changed()) await current.save({ transaction });
    return current;
  }

  const created = await ScanFinding.create(
    { ruleId: finding.ruleId, ScanToolId: toolId, ...values },
    { transaction },
  );
  existing.set(finding.ruleId, created);
  return created;
}

export async function importScan(
  scan: NormalizedScan,
  systemId: number,
  reportName: string,
  expectedBoundaryId?: number,
): Promise<ScanImportResult> {
  const result = {
    tool: scan.tool.name,
    target: scan.target.name,
    skipped: false,
    findings: scan.findings.length,
  };

  const system = await System.findByPk(systemId);
  if (!system) {
    throw createError({ statusCode: 400, statusMessage: `System ${systemId} not found.` });
  }
  const boundaryId = system.BoundaryId;
  if (expectedBoundaryId !== undefined && boundaryId !== expectedBoundaryId) {
    throw createError({ statusCode: 403, statusMessage: "System is not in this Boundary." });
  }
  const hash = scanHash(scan);

  await sequelize.transaction(async (transaction) => {
    const [tool] = await ScanTool.findOrCreate({
      where: { name: scan.tool.name },
      transaction,
    });

    const previousReports = await ScanReport.findAll({
      where: { SystemId: systemId, ScanToolId: tool.id, targetName: scan.target.name },
      include: [{ model: ScanReportItem }],
      transaction,
    });

    if (previousReports.some((report) => report.hash === hash)) {
      result.skipped = true;
      return;
    }

    const previousOverrides = new Map<string, ScanReportItem>();
    for (const report of previousReports) {
      for (const item of report.ScanReportItems ?? []) {
        if (item.statusOverride !== null || item.severityOverride !== null) {
          previousOverrides.set(
            overrideKey(item.ScanFindingId, item.componentName, item.locationPath),
            item,
          );
        }
      }
    }

    const ruleIds = [...new Set(scan.findings.map((f) => f.ruleId))];
    const existingFindings = new Map(
      (
        await ScanFinding.findAll({
          where: { ScanToolId: tool.id, ruleId: { [Op.in]: ruleIds } },
          transaction,
        })
      ).map((f) => [f.ruleId, f]),
    );

    const cveIds = [...new Set(scan.findings.flatMap((f) => f.cves))];
    const existingCves = new Map(
      (await Cve.findAll({ where: { cveId: { [Op.in]: cveIds } }, transaction })).map((c) => [
        c.cveId,
        c,
      ]),
    );

    const findingIds = new Set<number>();
    const linkedCves = new Set<string>();

    const report = await ScanReport.create(
      {
        name: reportName,
        targetKind: scan.target.kind,
        targetName: scan.target.name,
        targetDigest: scan.target.digest ?? null,
        toolVersion: scan.tool.version ?? null,
        scanDate: scan.scanDate ?? null,
        hash,
        SystemId: systemId,
        ScanToolId: tool.id,
      },
      { transaction },
    );

    const now = new Date().toISOString();
    const items = [];
    for (const finding of scan.findings) {
      const scanFinding = await upsertFinding(finding, tool.id, existingFindings, transaction);

      if (!findingIds.has(scanFinding.id)) {
        findingIds.add(scanFinding.id);
        for (const cveId of finding.cves) {
          let cve = existingCves.get(cveId);
          if (!cve) {
            cve = Cve.build();
            cve.cveId = cveId;
            if (finding.cvss3Vector) cve.updateByCvss3Vector(finding.cvss3Vector);
            await cve.save({ transaction });
            existingCves.set(cveId, cve);
          }
          const linkKey = `${cve.id}|${scanFinding.id}`;
          if (!linkedCves.has(linkKey)) {
            linkedCves.add(linkKey);
            await cve.addScanFinding(scanFinding, { transaction });
            await cve.addSystem(systemId, { transaction });
          }
        }
      }

      const component = finding.component;
      const location = finding.location;
      const previous = previousOverrides.get(
        overrideKey(scanFinding.id, component?.name, location?.path),
      );

      items.push({
        componentName: component?.name ?? null,
        componentVersion: component?.version ?? null,
        fixedVersion: component?.fixedVersion ?? null,
        purl: component?.purl ?? null,
        componentType: component?.type ?? null,
        locationPath: location?.path ?? null,
        locationLine: location?.line ?? null,
        locationUrl: location?.url ?? null,
        port: location?.port ?? null,
        evidence: finding.evidence ?? null,
        cvssScore: finding.cvssScore ?? null,
        cvss3Vector: finding.cvss3Vector ?? null,
        severityOverride: previous?.severityOverride ?? null,
        severityOverrideJustification: previous?.severityOverrideJustification ?? null,
        statusOverride: previous?.statusOverride ?? null,
        statusOverrideJustification: previous?.statusOverrideJustification ?? null,
        ScanReportId: report.id,
        ScanFindingId: scanFinding.id,
        // bulkCreate skips the per-instance beforeCreate timestamp hook
        lastUpdate: now,
        creationDate: now,
      });
    }
    await ScanReportItem.bulkCreate(items, { transaction });

    // POA&M fields live on an EvaluationItem shared by every system in the boundary
    const linkedToBoundary = new Set(
      (
        await ScanFinding_Boundary.findAll({
          where: { BoundaryId: boundaryId, ScanFindingId: { [Op.in]: [...findingIds] } },
          transaction,
        })
      ).map((row) => row.getDataValue("ScanFindingId")),
    );
    for (const findingId of findingIds) {
      if (linkedToBoundary.has(findingId)) continue;
      const evaluationItem = await EvaluationItem.create(undefined, { transaction });
      await ScanFinding_Boundary.create(
        { ScanFindingId: findingId, BoundaryId: boundaryId, EvaluationItemId: evaluationItem.id },
        { transaction },
      );
    }

    for (const previousReport of previousReports) {
      await previousReport.destroy({ transaction });
    }

    system.changed("lastUpdate", true);
    await system.save({ transaction });
  });

  return result;
}
