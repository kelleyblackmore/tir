import { DataTypes } from "sequelize";

// Tool-agnostic storage for non-Nessus scanner results (Trivy, Grype, and future
// SARIF / SBOM / DAST parsers). Mirrors the Nessus tables but keys findings on a
// text ruleId per tool and stores component / location data per result item.

const timestamps = () => ({
  lastUpdate: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  creationDate: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
});

const severities = ["Critical", "High", "Medium", "Low", "None"];

export const up = async ({ context: sequelize }) => {
  const queryInterface = sequelize.getQueryInterface();

  await queryInterface.createTable("ScanTools", {
    id: {
      type: DataTypes.INTEGER,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.TEXT,
      allowNull: false,
      unique: true,
    },
    ...timestamps(),
  });

  await queryInterface.createTable("ScanFindings", {
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
      values: severities,
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
    ScanToolId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "ScanTools",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ...timestamps(),
  });
  await queryInterface.addIndex("ScanFindings", ["ScanToolId", "ruleId"], { unique: true });

  await queryInterface.createTable("Cve_ScanFindings", {
    CveId: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      references: {
        model: "Cves",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ScanFindingId: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      references: {
        model: "ScanFindings",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
  });

  await queryInterface.createTable("ScanFinding_Boundaries", {
    ScanFindingId: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      references: {
        model: "ScanFindings",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    BoundaryId: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      references: {
        model: "Boundaries",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    EvaluationItemId: {
      type: DataTypes.INTEGER,
      references: {
        model: "EvaluationItems",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "SET NULL",
    },
  });

  await queryInterface.createTable("ScanReports", {
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
    SystemId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "Systems",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ScanToolId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "ScanTools",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ...timestamps(),
  });

  await queryInterface.createTable("ScanReportItems", {
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
    },
    severityOverrideJustification: {
      type: DataTypes.TEXT,
    },
    statusOverride: {
      type: DataTypes.ENUM,
      allowNull: true,
      values: ["Not_Reviewed", "Open", "NotAFinding", "Not_Applicable"],
    },
    statusOverrideJustification: {
      type: DataTypes.TEXT,
    },
    ScanReportId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "ScanReports",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ScanFindingId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "ScanFindings",
        key: "id",
      },
      onUpdate: "CASCADE",
      onDelete: "CASCADE",
    },
    ...timestamps(),
  });
};

export const down = async ({ context: sequelize }) => {
  const queryInterface = sequelize.getQueryInterface();
  await queryInterface.dropTable("ScanReportItems");
  await queryInterface.dropTable("ScanReports");
  await queryInterface.dropTable("ScanFinding_Boundaries");
  await queryInterface.dropTable("Cve_ScanFindings");
  await queryInterface.dropTable("ScanFindings");
  await queryInterface.dropTable("ScanTools");
  if (sequelize.getDialect() === "postgres") {
    await sequelize.query(`DROP TYPE IF EXISTS "enum_ScanFindings_severity";`);
    await sequelize.query(`DROP TYPE IF EXISTS "enum_ScanReportItems_statusOverride";`);
  }
};
