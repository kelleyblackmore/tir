/* eslint-disable no-use-before-define */
import {
  Model,
  DataTypes,
  type InferAttributes,
  type InferCreationAttributes,
  type CreationOptional,
  type ForeignKey,
  type NonAttribute,
} from "sequelize";
import type { ScanTool } from "./scanTool";
import type { ScanReportItem } from "./scanReportItem";
import type { Cve } from "./cve";
import { ScanSeverities, type ScanSeverity } from "~/types/scan";

// Definition of a finding as reported by a scan tool (a CVE for Trivy/Grype, a rule
// for SAST/DAST tools). Unique per (ScanToolId, ruleId); per-system occurrences are
// ScanReportItems.
export class ScanFinding extends Model<
  InferAttributes<ScanFinding>,
  InferCreationAttributes<ScanFinding>
> {
  declare id: CreationOptional<number>;
  declare ruleId: string;
  declare title: string;
  declare severity: ScanSeverity;
  declare description: string | null;
  declare solution: string | null;
  // Comma separated CWE ids
  declare cwes: string | null;
  // Newline separated URLs
  declare referenceUrls: string | null;
  declare ScanToolId: ForeignKey<ScanTool["id"]>;
  declare lastUpdate: CreationOptional<string>;
  declare creationDate: CreationOptional<string>;

  declare ScanTool?: NonAttribute<ScanTool>;
  declare ScanReportItems?: NonAttribute<ScanReportItem[]>;
  declare Cves?: NonAttribute<Cve[]>;
}

ScanFinding.init(
  {
    id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true,
    },
    ruleId: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    title: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    severity: {
      type: DataTypes.ENUM,
      values: [...ScanSeverities],
      allowNull: false,
    },
    description: {
      type: DataTypes.TEXT,
    },
    solution: {
      type: DataTypes.TEXT,
    },
    cwes: {
      type: DataTypes.TEXT,
    },
    referenceUrls: {
      type: DataTypes.TEXT,
    },
    lastUpdate: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    creationDate: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
  },
  {
    sequelize,
    modelName: "ScanFinding",
    timestamps: false,
  },
);
