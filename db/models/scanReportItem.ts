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
import type { ScanReport } from "./scanReport";
import type { ScanFinding } from "./scanFinding";

// One occurrence of a ScanFinding in a ScanReport, e.g. a CVE in a specific package
// version, or a SAST rule hit at a specific file and line.
export class ScanReportItem extends Model<
  InferAttributes<ScanReportItem>,
  InferCreationAttributes<ScanReportItem>
> {
  declare id: CreationOptional<number>;
  declare componentName: string | null;
  declare componentVersion: string | null;
  declare fixedVersion: string | null;
  declare purl: string | null;
  declare componentType: string | null;
  declare locationPath: string | null;
  declare locationLine: number | null;
  declare locationUrl: string | null;
  declare port: number | null;
  declare evidence: string | null;
  declare cvssScore: number | null;
  declare cvss3Vector: string | null;
  declare severityOverride: number | null;
  declare severityOverrideJustification: string | null;
  declare statusOverride: string | null;
  declare statusOverrideJustification: string | null;
  declare ScanReportId: ForeignKey<ScanReport["id"]>;
  declare ScanFindingId: ForeignKey<ScanFinding["id"]>;
  declare lastUpdate: CreationOptional<string>;
  declare creationDate: CreationOptional<string>;

  declare ScanReport?: NonAttribute<ScanReport>;
  declare ScanFinding?: NonAttribute<ScanFinding>;
}

ScanReportItem.init(
  {
    id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true,
    },
    componentName: {
      type: DataTypes.TEXT,
    },
    componentVersion: {
      type: DataTypes.TEXT,
    },
    fixedVersion: {
      type: DataTypes.TEXT,
    },
    purl: {
      type: DataTypes.TEXT,
    },
    componentType: {
      type: DataTypes.TEXT,
    },
    locationPath: {
      type: DataTypes.TEXT,
    },
    locationLine: {
      type: DataTypes.INTEGER,
    },
    locationUrl: {
      type: DataTypes.TEXT,
    },
    port: {
      type: DataTypes.INTEGER,
    },
    evidence: {
      type: DataTypes.TEXT,
    },
    cvssScore: {
      type: DataTypes.DECIMAL(3, 1),
    },
    cvss3Vector: {
      type: DataTypes.TEXT,
    },
    severityOverride: {
      type: DataTypes.INTEGER,
      allowNull: true,
    },
    severityOverrideJustification: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
    statusOverride: {
      type: DataTypes.ENUM,
      allowNull: true,
      values: ["Not_Reviewed", "Open", "NotAFinding", "Not_Applicable"],
    },
    statusOverrideJustification: {
      type: DataTypes.TEXT,
      allowNull: true,
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
    modelName: "ScanReportItem",
    timestamps: false,
  },
);
