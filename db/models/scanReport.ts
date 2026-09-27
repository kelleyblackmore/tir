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
import type { System } from "./system";
import type { ScanTool } from "./scanTool";
import type { ScanReportItem } from "./scanReportItem";

// One scan of one target (image, repo, host, ...) by one tool, assigned to a System.
// A system can hold many reports; re-importing the same tool + target replaces the
// previous report.
export class ScanReport extends Model<
  InferAttributes<ScanReport>,
  InferCreationAttributes<ScanReport>
> {
  declare id: CreationOptional<number>;
  declare name: string;
  declare targetKind: string;
  declare targetName: string;
  declare targetDigest: string | null;
  declare toolVersion: string | null;
  declare scanDate: string | null;
  declare hash: string;
  declare SystemId: ForeignKey<System["id"]>;
  declare ScanToolId: ForeignKey<ScanTool["id"]>;
  declare lastUpdate: CreationOptional<string>;
  declare creationDate: CreationOptional<string>;

  declare System?: NonAttribute<System>;
  declare ScanTool?: NonAttribute<ScanTool>;
  declare ScanReportItems?: NonAttribute<ScanReportItem[]>;
}

ScanReport.init(
  {
    id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    targetKind: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    targetName: {
      type: DataTypes.TEXT,
      allowNull: false,
    },
    targetDigest: {
      type: DataTypes.TEXT,
    },
    toolVersion: {
      type: DataTypes.TEXT,
    },
    scanDate: {
      type: DataTypes.TEXT,
    },
    hash: {
      type: DataTypes.TEXT,
      allowNull: false,
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
    modelName: "ScanReport",
    timestamps: false,
  },
);
