/* eslint-disable camelcase */
import { Cve } from "~/db/models/cve";
import {
  Boundary,
  EvaluationItem,
  ScanFinding,
  ScanFinding_Boundary,
  ScanReport,
  ScanReportItem,
  ScanTool,
  System,
} from "~/db/models";

// Findings from non-Nessus scanners (Trivy, Grype, ...) for a boundary, one entry
// per finding definition with every occurrence across the boundary's systems.
export default defineEventHandler(async (event) => {
  const query = getQuery(event);
  const BoundaryId = parseInt(query.BoundaryId?.toString() ?? "", 10);

  if (isNaN(BoundaryId)) {
    throw createError({
      statusCode: 400,
      statusMessage: `Invalid BoundaryId ${query.BoundaryId}`,
    });
  }

  const checkResult = await userCheck(event, undefined, BoundaryId, undefined);

  if (!checkResult.BoundaryRoleId) {
    throw createError({
      statusCode: 403,
      statusMessage: "Insufficient Permissions.",
    });
  }

  const findings = await ScanFinding.findAll({
    include: [
      { model: ScanTool, attributes: ["name"] },
      { model: Cve, attributes: ["cveId"], through: { attributes: [] } },
      {
        model: ScanFinding_Boundary,
        where: { BoundaryId },
        required: true,
        attributes: ["EvaluationItemId"],
        include: [{ model: EvaluationItem, attributes: ["id", "Scheduled_Completion_Date"] }],
      },
      {
        model: ScanReportItem,
        required: true,
        attributes: { exclude: ["lastUpdate", "creationDate", "ScanFindingId"] },
        include: [
          {
            model: ScanReport,
            required: true,
            attributes: ["id", "name", "targetKind", "targetName", "targetDigest", "scanDate"],
            include: [
              {
                model: System,
                required: true,
                attributes: ["id", "name"],
                include: [
                  { model: Boundary, attributes: [], where: { id: BoundaryId }, required: true },
                ],
              },
            ],
          },
        ],
      },
    ],
    order: [["id", "ASC"]],
  });

  return findings.map((finding) => ({
    id: finding.id,
    tool: finding.ScanTool?.name,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    description: finding.description,
    solution: finding.solution,
    cwes: finding.cwes?.split(",") ?? [],
    references: finding.referenceUrls?.split("\n") ?? [],
    cves: (finding.Cves ?? []).map((cve) => cve.cveId),
    evaluationItem: finding.getDataValue("ScanFinding_Boundaries" as any)?.[0]?.EvaluationItem,
    items: finding.ScanReportItems ?? [],
  }));
});
